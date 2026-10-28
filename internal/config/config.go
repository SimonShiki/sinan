// Loads sinan's YAML configuration.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	// SSIDs that identify the untrusted Wi-Fi (A). Any other Wi-Fi is C.
	UntrustedSSIDs []string `yaml:"untrusted_ssids"`

	// How the phone tethering uplink (B) is recognized.
	Tether struct {
		Drivers    []string `yaml:"drivers"`
		Interfaces []string `yaml:"interfaces"` // shell patterns
	} `yaml:"tether"`

	// Endpoints that must never use A: IPs, CIDRs or domains.
	Proxy []string `yaml:"proxy"`
	// Clash/mihomo YAML files (globs) whose proxies[].server are added to Proxy.
	ProxySources []string `yaml:"proxy_sources"`
	// Whitelist that always stays on A, overriding Proxy.
	Direct []string `yaml:"direct"`

	// DNS servers used to resolve domain rules. Empty: system resolver.
	DNS []string `yaml:"dns"`
	// How often rules are re-resolved, and how long resolved addresses are kept.
	Refresh time.Duration `yaml:"refresh"`
	Retain  time.Duration `yaml:"retain"`

	// Metric of the default route via A; must beat the other uplinks.
	Metric int `yaml:"metric"`
	// Policy routing table and rule priority for the block routes. The rule
	// must come before the proxy client's own rules (FlClash uses 9000+).
	Table        int `yaml:"table"`
	RulePriority int `yaml:"rule_priority"`
}

func Load(path string) (*Config, error) {
	c := &Config{
		Refresh:      10 * time.Minute,
		Retain:       24 * time.Hour,
		Metric:       10,
		Table:        7101,
		RulePriority: 8999,
	}
	c.Tether.Drivers = []string{"rndis_host", "cdc_ncm", "cdc_ether", "ipheth"}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(data, c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if c.Refresh <= 0 || c.Retain < 0 || c.Table <= 0 || c.RulePriority <= 0 {
		return nil, fmt.Errorf("%s: refresh, table and rule_priority must be positive, retain not negative", path)
	}
	return c, nil
}
