// Package ruleset turns proxy/direct rules into a longest-prefix-match table.
package ruleset

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

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
			if a, err := netip.ParseAddr(strings.Trim(e, "[]")); err == nil {
				r.Prefixes = append(r.Prefixes, host(a))
			} else if isDomain(e) {
				r.Domains = append(r.Domains, strings.ToLower(strings.TrimSuffix(e, ".")))
			} else {
				return r, fmt.Errorf("invalid rule %q", e)
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

func isDomain(s string) bool {
	if len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	for _, c := range s {
		if !(c == '-' || c == '.' || c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return true
}
