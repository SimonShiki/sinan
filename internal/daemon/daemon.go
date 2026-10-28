// Ties detection, rules and enforcement into one reconcile loop.
package daemon

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/SimonShiki/sinan/internal/config"
	"github.com/SimonShiki/sinan/internal/netenv"
	"github.com/SimonShiki/sinan/internal/route"
	"github.com/SimonShiki/sinan/internal/ruleset"
	"github.com/SimonShiki/sinan/internal/steer"
)

const (
	settle = 300 * time.Millisecond // debounce for netlink bursts
	poll   = 15 * time.Second       // catches SSID changes and source edits
)

type Daemon struct {
	cfg   *config.Config
	match netenv.Matcher
	route route.Manager
	res   *ruleset.Resolver
	steer *steer.Steer

	env    netenv.Env
	table  map[netip.Prefix]bool
	mtimes map[string]time.Time
	status string
}

func New(cfg *config.Config) *Daemon {
	return &Daemon{
		cfg: cfg,
		match: netenv.Matcher{
			UntrustedSSIDs: cfg.UntrustedSSIDs,
			TetherDrivers:  cfg.Tether.Drivers,
			TetherNames:    cfg.Tether.Interfaces,
			IgnoreProto:    int(route.Proto),
		},
		route: route.Manager{Table: cfg.Table, Priority: cfg.RulePriority, Metric: cfg.Metric},
		res:   &ruleset.Resolver{Servers: cfg.DNS, Retain: cfg.Retain, Timeout: 3 * time.Second},
	}
}

// Validate checks that all static rules parse.
func (d *Daemon) Validate() error {
	for _, rules := range [][]string{d.cfg.Proxy, d.cfg.Direct} {
		if _, err := ruleset.Parse(rules); err != nil {
			return err
		}
	}
	return nil
}

// Check prints what sinan would do right now without changing anything.
func (d *Daemon) Check(ctx context.Context) error {
	env, err := netenv.Scan(d.match)
	if err != nil {
		return err
	}
	fmt.Printf("A (untrusted Wi-Fi): %s\nB (tethering):       %s\ndefault uplink:      %s\n",
		describe(env.A), describe(env.B), env.Default)
	table, err := d.buildTable(ctx, dnsDevice(env))
	if err != nil {
		return err
	}
	fmt.Printf("endpoint table (%d entries):\n", len(table))
	keys := slices.SortedFunc(maps.Keys(table), func(a, b netip.Prefix) int {
		return cmp.Or(a.Addr().Compare(b.Addr()), a.Bits()-b.Bits())
	})
	for _, p := range keys {
		verdict := "proxy -> B"
		if !table[p] {
			verdict = "direct (whitelist)"
		}
		fmt.Printf("  %-43s %s\n", p, verdict)
	}
	s, err := steer.Load()
	if err != nil {
		return fmt.Errorf("load eBPF: %w", err)
	}
	fmt.Println("eBPF programs: verified and loadable")
	return s.Close()
}

// Run enforces the policy until ctx is cancelled, then removes all traces.
func (d *Daemon) Run(ctx context.Context) error {
	s, err := steer.Load()
	if err != nil {
		return fmt.Errorf("load eBPF: %w", err)
	}
	d.steer = s
	defer d.teardown()
	if err := d.route.Clear(); err != nil {
		slog.Warn("clearing leftovers", "err", err)
	}

	if d.env, err = netenv.Scan(d.match); err != nil {
		return err
	}
	d.sourcesChanged()
	if d.table, err = d.buildTable(ctx, dnsDevice(d.env)); err != nil {
		return err
	}
	d.reconcile()

	events := make(chan struct{}, 1)
	if err := subscribe(ctx, events); err != nil {
		return err
	}
	tables := make(chan map[netip.Prefix]bool, 1)
	building := false
	rebuild := func() {
		if building {
			return
		}
		building = true
		dev := dnsDevice(d.env)
		go func() {
			t, err := d.buildTable(ctx, dev)
			if err != nil {
				slog.Error("rebuilding endpoint table, keeping the previous one", "err", err)
			}
			tables <- t
		}()
	}
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	refresh := time.NewTicker(d.cfg.Refresh)
	defer refresh.Stop()
	tick := time.NewTicker(poll)
	defer tick.Stop()
	debounce := time.NewTimer(settle)
	debounce.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-events:
			debounce.Reset(settle)
		case <-debounce.C:
			d.reconcile()
		case <-tick.C:
			if d.sourcesChanged() {
				rebuild()
			}
			d.reconcile()
		case <-refresh.C:
			rebuild()
		case <-hup:
			rebuild()
		case t := <-tables:
			building = false
			if t != nil {
				d.table = t
				d.reconcile()
			}
		}
	}
}

// reconcile brings kernel state in line with the current environment. It is
// idempotent and cheap when nothing changed.
func (d *Daemon) reconcile() {
	env, err := netenv.Scan(d.match)
	if err != nil {
		slog.Error("scanning uplinks", "err", err)
		return
	}
	d.env = env
	if env.A == nil {
		err := d.route.Clear()
		d.steer.Detach()
		d.report("inactive: system defaults", err)
		return
	}
	// Guard A before making it the preferred uplink.
	if err := d.steer.Sync(env.A, env.B, d.table); err != nil {
		// Without the eBPF guard, at least refuse new connections to endpoints.
		err = errors.Join(err, d.route.Prefer(nil), d.route.Block(d.table, true, true))
		d.report("steering FAILED, proxy endpoints blocked", err)
		return
	}
	v4, v6 := steer.Capable(env.B)
	err = errors.Join(d.route.Prefer(env.A), d.route.Block(d.table, !v4, !v6))
	mode := "proxy endpoints blocked (no B)"
	switch {
	case v4 && v6:
		mode = fmt.Sprintf("proxy endpoints via %s", env.B.Name)
	case v4 || v6:
		mode = fmt.Sprintf("proxy endpoints via %s (IPv4=%t IPv6=%t, rest blocked)", env.B.Name, v4, v6)
	}
	d.report(fmt.Sprintf("active on %s (%s): %s, %d table entries", env.A.Name, env.A.SSID, mode, len(d.table)), err)
}

func (d *Daemon) report(status string, err error) {
	if err != nil {
		slog.Error(status, "err", err)
		d.status = ""
		return
	}
	if status != d.status {
		slog.Info(status)
		d.status = status
	}
}

func (d *Daemon) teardown() {
	if err := d.route.Clear(); err != nil {
		slog.Error("removing routes", "err", err)
	}
	d.steer.Close()
	slog.Info("stopped, system defaults restored")
}

func (d *Daemon) buildTable(ctx context.Context, dev string) (map[netip.Prefix]bool, error) {
	proxy, err := ruleset.Parse(d.cfg.Proxy)
	if err != nil {
		return nil, err
	}
	servers, err := ruleset.ClashServers(d.cfg.ProxySources)
	if err != nil {
		return nil, err
	}
	imported, err := ruleset.Parse(servers)
	if err != nil {
		return nil, err
	}
	direct, err := ruleset.Parse(d.cfg.Direct)
	if err != nil {
		return nil, err
	}
	// Subscriptions list many nodes on few servers: resolve each name once.
	proxyDomains := slices.Compact(slices.Sorted(slices.Values(append(proxy.Domains, imported.Domains...))))
	proxyPrefixes := append(proxy.Prefixes, imported.Prefixes...)
	proxyPrefixes = append(proxyPrefixes, d.res.Resolve(ctx, proxyDomains, dev)...)
	directPrefixes := append(direct.Prefixes, d.res.Resolve(ctx, direct.Domains, dev)...)
	return ruleset.Table(proxyPrefixes, directPrefixes), nil
}

// sourcesChanged reports whether any proxy source file appeared, disappeared
// or was modified since the last call.
func (d *Daemon) sourcesChanged() bool {
	now := map[string]time.Time{}
	for _, pat := range d.cfg.ProxySources {
		files, _ := filepath.Glob(pat)
		for _, f := range files {
			if st, err := os.Stat(f); err == nil {
				now[f] = st.ModTime()
			}
		}
	}
	changed := len(now) != len(d.mtimes)
	for f, t := range now {
		if !d.mtimes[f].Equal(t) {
			changed = true
		}
	}
	d.mtimes = now
	return changed
}

// subscribe signals events on any link, address or route change.
func subscribe(ctx context.Context, events chan<- struct{}) error {
	notify := func() {
		select {
		case events <- struct{}{}:
		default:
		}
	}
	onErr := func(err error) { slog.Warn("netlink subscription", "err", err) }
	links := make(chan netlink.LinkUpdate)
	addrs := make(chan netlink.AddrUpdate)
	routes := make(chan netlink.RouteUpdate)
	err := errors.Join(
		netlink.LinkSubscribeWithOptions(links, ctx.Done(), netlink.LinkSubscribeOptions{ErrorCallback: onErr}),
		netlink.AddrSubscribeWithOptions(addrs, ctx.Done(), netlink.AddrSubscribeOptions{ErrorCallback: onErr}),
		netlink.RouteSubscribeWithOptions(routes, ctx.Done(), netlink.RouteSubscribeOptions{ErrorCallback: onErr}),
	)
	if err != nil {
		return err
	}
	// The library closes a channel when its subscription dies; the periodic
	// poll keeps things working after that.
	go forward(links, func(netlink.LinkUpdate) bool { return true }, notify)
	go forward(addrs, func(netlink.AddrUpdate) bool { return true }, notify)
	go forward(routes, func(u netlink.RouteUpdate) bool { return u.Protocol != route.Proto }, notify)
	return nil
}

func forward[T any](ch <-chan T, relevant func(T) bool, notify func()) {
	for u := range ch {
		if relevant(u) {
			notify()
		}
	}
}

// dnsDevice is where rule resolution leaves the host: the preferred uplink,
// bound directly so a TUN-mode proxy cannot hijack or fake the answers.
func dnsDevice(env netenv.Env) string {
	if env.A != nil {
		return env.A.Name
	}
	return env.Default
}

func describe(u *netenv.Uplink) string {
	if u == nil {
		return "-"
	}
	s := fmt.Sprintf("%s driver=%s gw4=%v src4=%v gw6=%v src6=%v ether=%t", u.Name, u.Driver, u.Gw4, u.Addr4, u.Gw6, u.Addr6, u.Ether)
	if u.SSID != "" {
		s += fmt.Sprintf(" ssid=%q", u.SSID)
	}
	return s
}
