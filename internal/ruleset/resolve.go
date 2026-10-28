package ruleset

import (
	"context"
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
	now := time.Now()
	type answer struct {
		domain string
		addrs  []netip.Addr
	}
	ch := make(chan answer)
	var wg sync.WaitGroup
	for _, d := range domains {
		for _, res := range resolvers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(ctx, r.Timeout)
				defer cancel()
				addrs, _ := res.LookupNetIP(ctx, "ip", d)
				ch <- answer{d, addrs}
			}()
		}
	}
	go func() { wg.Wait(); close(ch) }()

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.seen == nil {
		r.seen = map[string]map[netip.Addr]time.Time{}
	}
	for a := range ch {
		if r.seen[a.domain] == nil {
			r.seen[a.domain] = map[netip.Addr]time.Time{}
		}
		for _, ip := range a.addrs {
			r.seen[a.domain][ip.Unmap()] = now
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

func (r *Resolver) resolvers(dev string) []*net.Resolver {
	if len(r.Servers) == 0 {
		return []*net.Resolver{net.DefaultResolver}
	}
	d := net.Dialer{Control: func(_, _ string, c syscall.RawConn) error {
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
	var out []*net.Resolver
	for _, s := range r.Servers {
		addr := s
		if _, _, err := net.SplitHostPort(s); err != nil {
			addr = net.JoinHostPort(s, "53")
		}
		out = append(out, &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return d.DialContext(ctx, network, addr)
			},
		})
	}
	return out
}
