package ruleset

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/net/dns/dnsmessage"
)

// Server is a DNS server for rule resolution:
//
//	223.5.5.5, 223.5.5.5:53       plain DNS (UDP, TCP on truncation)
//	tls://223.5.5.5[:853]         DNS over TLS
//	https://223.5.5.5[/dns-query] DNS over HTTPS (RFC 8484)
//
// The host must be an IP literal: resolving a server name would need another,
// unencrypted lookup that a TUN-mode proxy may answer with a fake address.
// Certificates are verified against the IP, which public resolvers
// (AliDNS, DNSPod, Cloudflare, Google, Quad9) include in their certificates.
type Server struct {
	Proto string // "udp", "tls" or "https"
	Addr  string // ip:port
	URL   string // https only
}

func ParseServer(s string) (Server, error) {
	s = strings.TrimSpace(s)
	scheme, rest, ok := strings.Cut(s, "://")
	if !ok {
		scheme, rest = "udp", s
	} else {
		scheme = strings.ToLower(scheme)
	}
	var srv Server
	switch scheme {
	case "udp", "tls":
		if strings.ContainsAny(rest, "/?#") {
			return srv, fmt.Errorf("dns %q: unexpected path", s)
		}
		addr, err := ipPort(rest, map[string]string{"udp": "53", "tls": "853"}[scheme])
		if err != nil {
			return srv, fmt.Errorf("dns %q: %w", s, err)
		}
		return Server{Proto: scheme, Addr: addr}, nil
	case "https":
		u, err := url.Parse(s)
		if err != nil {
			return srv, fmt.Errorf("dns %q: %w", s, err)
		}
		if u.User != nil || u.Fragment != "" {
			return srv, fmt.Errorf("dns %q: user info and fragments are not allowed", s)
		}
		addr, err := ipPort(u.Host, "443")
		if err != nil {
			return srv, fmt.Errorf("dns %q: %w", s, err)
		}
		if u.Path == "" {
			u.Path = "/dns-query"
		}
		return Server{Proto: "https", Addr: addr, URL: u.String()}, nil
	}
	return srv, fmt.Errorf("dns %q: unknown scheme %q (want udp, tls or https)", s, scheme)
}

func ParseServers(ss []string) ([]Server, error) {
	var out []Server
	for _, s := range ss {
		srv, err := ParseServer(s)
		if err != nil {
			return nil, err
		}
		out = append(out, srv)
	}
	return out, nil
}

// ipPort accepts "ip", "ip:port", "[ipv6]" and "[ipv6]:port".
func ipPort(s, defPort string) (string, error) {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		host, port = s, defPort
	}
	ip, ok := parseIPLiteral(host)
	if !ok {
		return "", fmt.Errorf("host must be an IP address")
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return "", fmt.Errorf("port must be between 1 and 65535")
	}
	return net.JoinHostPort(ip.String(), strconv.FormatUint(n, 10)), nil
}

type lookuper interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// lookuper returns a resolver for srv whose connections are made with d,
// and a function releasing its idle connections.
func (srv Server) lookuper(d *net.Dialer) (lookuper, func()) {
	switch srv.Proto {
	case "tls":
		// The Go resolver uses length-prefixed TCP framing for any conn that
		// is not a PacketConn, which is exactly DNS over TLS.
		host, _, _ := net.SplitHostPort(srv.Addr)
		return &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
				td := tls.Dialer{NetDialer: d, Config: &tls.Config{ServerName: host}}
				return td.DialContext(ctx, "tcp", srv.Addr)
			},
		}, func() {}
	case "https":
		t := &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return d.DialContext(ctx, "tcp", srv.Addr)
			},
			ForceAttemptHTTP2: true,
		}
		return &doh{url: srv.URL, client: &http.Client{Transport: t}}, t.CloseIdleConnections
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, srv.Addr)
		},
	}, func() {}
}

// doh is a minimal DNS-over-HTTPS client that only looks up addresses.
type doh struct {
	url    string
	client *http.Client
}

func (r *doh) LookupNetIP(ctx context.Context, _, host string) ([]netip.Addr, error) {
	name, err := dnsmessage.NewName(strings.TrimSuffix(host, ".") + ".")
	if err != nil {
		return nil, err
	}
	var (
		mu    sync.Mutex
		addrs []netip.Addr
		errs  []error
		wg    sync.WaitGroup
	)
	for _, t := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		wg.Go(func() {
			a, err := r.query(ctx, name, t)
			mu.Lock()
			defer mu.Unlock()
			addrs = append(addrs, a...)
			errs = append(errs, err)
		})
	}
	wg.Wait()
	if len(addrs) == 0 {
		return nil, errors.Join(errs...)
	}
	return addrs, nil
}

func (r *doh) query(ctx context.Context, name dnsmessage.Name, t dnsmessage.Type) ([]netip.Addr, error) {
	// ID 0 as recommended by RFC 8484 for HTTP caching.
	q := dnsmessage.Message{
		Header:    dnsmessage.Header{RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: name, Type: t, Class: dnsmessage.ClassINET}},
	}
	body, err := q.Pack()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", r.url, resp.Status)
	}
	if body, err = io.ReadAll(io.LimitReader(resp.Body, 65536)); err != nil {
		return nil, err
	}

	var p dnsmessage.Parser
	h, err := p.Start(body)
	if err != nil {
		return nil, err
	}
	if h.RCode != dnsmessage.RCodeSuccess {
		return nil, fmt.Errorf("%s %s: %s", name, t, h.RCode)
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, err
	}
	// A CNAME chain ends in the address records; all of them belong to name.
	var out []netip.Addr
	for {
		ah, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		switch ah.Type {
		case dnsmessage.TypeA:
			a, err := p.AResource()
			if err != nil {
				return out, err
			}
			out = append(out, netip.AddrFrom4(a.A))
		case dnsmessage.TypeAAAA:
			a, err := p.AAAAResource()
			if err != nil {
				return out, err
			}
			out = append(out, netip.AddrFrom16(a.AAAA))
		default:
			if err := p.SkipAnswer(); err != nil {
				return out, err
			}
		}
	}
}
