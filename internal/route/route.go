// Package route manages the few routes and rules sinan adds. Every route is
// tagged with Proto so it can be found and removed again, even after a crash.
package route

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/SimonShiki/sinan/internal/netenv"
)

// the rtnetlink protocol id marking sinan's routes.
const Proto = netlink.RouteProtocol(83)

var families = []int{netlink.FAMILY_V4, netlink.FAMILY_V6}

// owns a policy table and the rule pointing at it.
type Manager struct {
	Table    int
	Priority int
	Metric   int
}

// Adds a default route via A to the main table with Metric, so A wins
// over other uplinks for everything that is not steered. A nil a removes it.
func (m Manager) Prefer(a *netenv.Uplink) error {
	if a == nil {
		return syncTable(unix.RT_TABLE_MAIN, nil)
	}
	var want []netlink.Route
	for _, gw := range []netip.Addr{a.Gw4, a.Gw6} {
		if !gw.IsValid() {
			continue
		}
		want = append(want, netlink.Route{
			LinkIndex: a.Index,
			Gw:        gw.AsSlice(),
			Priority:  m.Metric,
		})
	}
	return syncTable(unix.RT_TABLE_MAIN, want)
}

// Makes proxy endpoints unreachable for the families B cannot carry, so
// connections fail fast instead of timing out on the eBPF drop. Whitelisted
// prefixes inside them get a throw route, deferring to the next rule.
func (m Manager) Block(table map[netip.Prefix]bool, block4, block6 bool) error {
	var want []netlink.Route
	for p, proxy := range table {
		if p.Addr().Is4() && !block4 || p.Addr().Is6() && !block6 {
			continue
		}
		typ := unix.RTN_THROW
		if proxy {
			typ = unix.RTN_UNREACHABLE
		}
		want = append(want, netlink.Route{Dst: ipnet(p), Type: typ})
	}
	if err := syncTable(m.Table, want); err != nil {
		return err
	}
	return m.syncRules(len(want) > 0)
}

// Removes everything sinan added.
func (m Manager) Clear() error {
	return errors.Join(
		m.Prefer(nil),
		syncTable(m.Table, nil),
		m.syncRules(false),
	)
}

// Makes our routes in table exactly match want.
func syncTable(table int, want []netlink.Route) error {
	for i := range want {
		want[i].Table = table
		want[i].Protocol = Proto
		if want[i].Type == 0 {
			want[i].Type = unix.RTN_UNICAST
		}
	}
	var have []netlink.Route
	for _, f := range families {
		rs, err := netlink.RouteListFiltered(f, &netlink.Route{Table: table, Protocol: Proto},
			netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL)
		if err != nil {
			return err
		}
		have = append(have, rs...)
	}
	var errs []error
	for _, r := range have {
		if !slices.ContainsFunc(want, func(w netlink.Route) bool { return same(r, w) }) {
			if err := netlink.RouteDel(&r); err != nil {
				errs = append(errs, fmt.Errorf("delete route %s: %w", r, err))
			}
		}
	}
	for _, w := range want {
		if !slices.ContainsFunc(have, func(r netlink.Route) bool { return same(r, w) }) {
			if err := netlink.RouteAdd(&w); err != nil {
				errs = append(errs, fmt.Errorf("add route %s: %w", w, err))
			}
		}
	}
	return errors.Join(errs...)
}

func same(a, b netlink.Route) bool {
	return a.Type == b.Type && a.LinkIndex == b.LinkIndex && a.Priority == b.Priority &&
		a.Gw.Equal(b.Gw) && prefix(a.Dst) == prefix(b.Dst)
}

func (m Manager) syncRules(present bool) error {
	var errs []error
	for _, f := range families {
		rules, err := netlink.RuleListFiltered(f, &netlink.Rule{Table: m.Table}, netlink.RT_FILTER_TABLE)
		if err != nil {
			return err
		}
		found := false
		for _, r := range rules {
			if present && !found && r.Priority == m.Priority {
				found = true
				continue
			}
			if err := netlink.RuleDel(&r); err != nil {
				errs = append(errs, err)
			}
		}
		if present && !found {
			r := netlink.NewRule()
			r.Family, r.Table, r.Priority = f, m.Table, m.Priority
			if err := netlink.RuleAdd(r); err != nil {
				errs = append(errs, fmt.Errorf("add rule: %w", err))
			}
		}
	}
	return errors.Join(errs...)
}

func ipnet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}

// normalizes a route destination; default routes become the zero value.
func prefix(n *net.IPNet) netip.Prefix {
	if n == nil {
		return netip.Prefix{}
	}
	ones, _ := n.Mask.Size()
	a, _ := netip.AddrFromSlice(n.IP)
	if ones == 0 {
		return netip.Prefix{}
	}
	return netip.PrefixFrom(a.Unmap(), ones)
}
