// Package ruleset turns proxy/direct rules into a longest-prefix-match table.
package ruleset

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/net/idna"
	"gopkg.in/yaml.v3"
)

// Rules are parsed rule entries: literal prefixes plus domains to resolve.
type Rules struct {
	Prefixes []netip.Prefix
	Domains  []string
}

// Accepts IPs, CIDRs and domain names.
func Parse(entries []string) (Rules, error) {
	var r Rules
	for _, e := range entries {
		e = strings.TrimSpace(e)
		switch {
		case e == "":
		case strings.Contains(e, "/"):
			p, err := netip.ParsePrefix(e)
			if err != nil {
				return r, err
			}
			if p.Addr().Is4In6() && p.Bits() >= 96 {
				p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
			}
			r.Prefixes = append(r.Prefixes, p.Masked())
		default:
			if a, ok := parseIPLiteral(e); ok {
				r.Prefixes = append(r.Prefixes, host(a))
			} else {
				domain, err := normalizeDomain(e)
				if err != nil {
					return r, fmt.Errorf("invalid rule %q: %w", e, err)
				}
				r.Domains = append(r.Domains, domain)
			}
		}
	}
	return r, nil
}

// Collects `proxies[].server` from Clash/mihomo style YAML files
// matching the given glob patterns.
func ClashServers(patterns []string) ([]string, error) {
	var out []string
	for _, pat := range patterns {
		files, err := filepath.Glob(pat)
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			data, err := os.ReadFile(f)
			if err != nil {
				return nil, err
			}
			var doc struct {
				Proxies []struct {
					Server string `yaml:"server"`
				} `yaml:"proxies"`
			}
			if err := yaml.Unmarshal(data, &doc); err != nil {
				return nil, fmt.Errorf("%s: %w", f, err)
			}
			for _, p := range doc.Proxies {
				if p.Server != "" {
					out = append(out, p.Server)
				}
			}
		}
	}
	return out, nil
}

// Table builds the endpoint table: true marks a proxy endpoint (must use B),
// false a whitelisted prefix (stays on A). Proxy prefixes inside a whitelisted
// one are dropped and whitelisted prefixes inside a proxy one are kept, so
// that longest-prefix match always gives the whitelist precedence.
func Table(proxy, direct []netip.Prefix) map[netip.Prefix]bool {
	t := map[netip.Prefix]bool{}
	for _, p := range proxy {
		if !coveredBy(p, direct) {
			t[p] = true
		}
	}
	for _, d := range direct {
		if coveredBy(d, proxy) {
			t[d] = false
		}
	}
	return t
}

// Reports whether p lies within any of the prefixes.
func coveredBy(p netip.Prefix, in []netip.Prefix) bool {
	for _, q := range in {
		if q.Bits() <= p.Bits() && q.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

func host(a netip.Addr) netip.Prefix {
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen())
}

// parseIPLiteral accepts an IP with optional matching brackets, without a zone.
// Routing prefixes cannot represent scoped IPv6 addresses.
func parseIPLiteral(s string) (netip.Addr, bool) {
	if strings.ContainsAny(s, "[]") {
		if len(s) < 2 || s[0] != '[' || s[len(s)-1] != ']' || strings.ContainsAny(s[1:len(s)-1], "[]") {
			return netip.Addr{}, false
		}
		s = s[1 : len(s)-1]
	}
	a, err := netip.ParseAddr(s)
	return a, err == nil && a.Zone() == ""
}

var domainIDNA = idna.New(idna.MapForLookup(), idna.BidiRule(), idna.VerifyDNSLength(true))

// normalizeDomain converts a DNS hostname to its lowercase ASCII form.
// Keep the rule format's requirement for at least two labels.
func normalizeDomain(s string) (string, error) {
	// Strip exactly one optional root dot; IDNA validates the remaining labels.
	ascii, err := domainIDNA.ToASCII(strings.TrimSuffix(s, "."))
	if err != nil {
		return "", err
	}
	if !strings.Contains(ascii, ".") {
		return "", fmt.Errorf("domain must have at least two labels")
	}
	return ascii, nil
}
