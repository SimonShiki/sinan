package ruleset

import (
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func prefixes(s ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range s {
		out = append(out, netip.MustParsePrefix(p))
	}
	return out
}

func TestParse(t *testing.T) {
	r, err := Parse([]string{"1.2.3.4", "10.0.0.1/8", "2001:db8::1", "[2001:db8::2]", "::ffff:1.1.1.1", "::ffff:5.6.7.8/120", "Node.Example.com.", " "})
	if err != nil {
		t.Fatal(err)
	}
	want := prefixes("1.2.3.4/32", "10.0.0.0/8", "2001:db8::1/128", "2001:db8::2/128", "1.1.1.1/32", "5.6.7.0/24")
	if !slices.Equal(r.Prefixes, want) {
		t.Errorf("prefixes = %v, want %v", r.Prefixes, want)
	}
	if !slices.Equal(r.Domains, []string{"node.example.com"}) {
		t.Errorf("domains = %v", r.Domains)
	}
	for _, bad := range []string{"localhost", "1.2.3.4/33", "a b.com"} {
		if _, err := Parse([]string{bad}); err == nil {
			t.Errorf("Parse(%q) succeeded", bad)
		}
	}
}

func TestTableWhitelistWins(t *testing.T) {
	got := Table(
		prefixes("192.0.2.10/32", "198.51.100.0/24", "203.0.113.5/32", "2001:db8::/32"),
		prefixes("192.0.2.0/24", "198.51.100.7/32", "203.0.113.200/32", "203.0.113.5/32"),
	)
	want := map[netip.Prefix]bool{
		// 192.0.2.10 is inside a whitelisted /24: dropped, the /24 is irrelevant.
		netip.MustParsePrefix("198.51.100.0/24"): true,
		netip.MustParsePrefix("198.51.100.7/32"): false, // carve-out inside a proxy range
		netip.MustParsePrefix("203.0.113.5/32"):  false, // identical entry: whitelist wins
		netip.MustParsePrefix("2001:db8::/32"):   true,
	}
	if !maps.Equal(got, want) {
		t.Errorf("Table = %v, want %v", got, want)
	}
}

func TestClashServers(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(`
mode: rule
proxies:
  - {name: hk, type: vless, server: hk.example.com, port: 443}
  - {name: ip, type: ss, server: 203.0.113.9, port: 8388}
  - {name: dir, type: direct}
proxy-groups: []
`), 0o644)
	got, err := ClashServers([]string{filepath.Join(dir, "*.yaml")})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"hk.example.com", "203.0.113.9"}) {
		t.Errorf("ClashServers = %v", got)
	}
}
