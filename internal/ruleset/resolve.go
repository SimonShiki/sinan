package ruleset

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Resolver resolves domain rules against a fixed set of DNS servers and
// remembers every answer for Retain, so an endpoint is still known while a
// client may be connected to an address it resolved earlier.
type Resolver struct {
	Servers []string      // "ip" or "ip:port"; empty uses the system resolver
	Retain  time.Duration // how long a seen address stays in the result
	Timeout time.Duration

	mu   sync.Mutex
	seen map[string]map[netip.Addr]time.Time
}

// returns the union of all current and retained addresses of domains.
// Queries leave through device dev (if set), bypassing TUN-based DNS hijacking
// the same way proxy clients do.
func (r *Resolver) Resolve(ctx context.Context, domains []string, dev string) []netip.Prefix {
	resolvers := r.resolvers(dev)
	defer func() {
		for _, res := range resolvers {
			res.close()
		}
	}()
	now := time.Now()
	type answer struct {
		domain string
		server int
		addrs  []netip.Addr
		err    error
	}
	ch := make(chan answer)
	var wg sync.WaitGroup
	for _, d := range domains {
		for i, res := range resolvers {
			wg.Go(func() {
				ctx, cancel := context.WithTimeout(ctx, r.Timeout)
				defer cancel()
				addrs, err := res.LookupNetIP(ctx, "ip", d)
				ch <- answer{d, i, addrs, err}
			})
		}
	}
	go func() { wg.Wait(); close(ch) }()

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.seen == nil {
		r.seen = map[string]map[netip.Addr]time.Time{}
	}
	answered := make([]bool, len(resolvers))
	lastErr := make([]error, len(resolvers))
	for a := range ch {
		if r.seen[a.domain] == nil {
			r.seen[a.domain] = map[netip.Addr]time.Time{}
		}
		for _, ip := range a.addrs {
			r.seen[a.domain][ip.Unmap()] = now
		}
		if len(a.addrs) > 0 {
			answered[a.server] = true
		} else if a.err != nil {
			lastErr[a.server] = a.err
		}
	}
	// A server that resolves nothing is likely misconfigured or unreachable;
	// say so instead of silently treating its endpoints as direct.
	for i, res := range resolvers {
		if !answered[i] && lastErr[i] != nil && ctx.Err() == nil {
			slog.Warn("dns server resolved no rule domain", "server", res.name, "dev", dev, "err", lastErr[i])
		}
	}
	var out []netip.Prefix
	for _, d := range domains {
		for ip, t := range r.seen[d] {
			if now.Sub(t) > r.Retain {
				delete(r.seen[d], ip)
				continue
			}
			out = append(out, host(ip))
		}
	}
	return out
}

type resolver struct {
	lookuper
	name  string
	close func()
}

// resolvers returns one resolver per valid configured server (Servers are
// validated with ParseServers at startup).
func (r *Resolver) resolvers(dev string) []resolver {
	if len(r.Servers) == 0 {
		return []resolver{{net.DefaultResolver, "system", func() {}}}
	}
	d := &net.Dialer{Control: func(_, _ string, c syscall.RawConn) error {
		if dev == "" {
			return nil
		}
		var serr error
		err := c.Control(func(fd uintptr) { serr = unix.BindToDevice(int(fd), dev) })
		if err != nil {
			return err
		}
		return serr
	}}
	var out []resolver
	for _, s := range r.Servers {
		srv, err := ParseServer(s)
		if err != nil {
			continue
		}
		l, closeIdle := srv.lookuper(d)
		out = append(out, resolver{l, s, closeIdle})
	}
	return out
}
