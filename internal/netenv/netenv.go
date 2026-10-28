// Discovers the uplinks sinan cares about straight from the
// kernel (rtnetlink, nl80211, sysfs), independent of any network manager.
package netenv

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"

	"github.com/mdlayher/wifi"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Uplink is an interface with a default route in the main table.
type Uplink struct {
	Name   string
	Index  int
	MAC    net.HardwareAddr
	Ether  bool   // has an Ethernet header (needed for steering)
	SSID   string // Wi-Fi only
	Driver string

	Gw4, Gw6     netip.Addr
	Addr4, Addr6 netip.Addr
	metric       int
}

// Env is a snapshot of the uplinks.
type Env struct {
	A       *Uplink // Wi-Fi associated to an untrusted SSID
	B       *Uplink // phone tethering
	Default string  // interface of the preferred default route
}

// Matcher tells which uplinks are A and B.
type Matcher struct {
	UntrustedSSIDs []string
	TetherDrivers  []string
	TetherNames    []string // shell patterns
	IgnoreProto    int      // routes of this protocol (sinan's own) are not uplinks
}

// Scan takes a snapshot of the current uplinks.
func Scan(m Matcher) (Env, error) {
	ups, err := uplinks(m.IgnoreProto)
	if err != nil {
		return Env{}, err
	}
	ssids := wifiSSIDs()
	var env Env
	best := -1
	for _, u := range ups {
		if best < 0 || u.metric < best {
			best, env.Default = u.metric, u.Name
		}
		u.SSID = ssids[u.Index]
		if env.A == nil && u.SSID != "" && slices.Contains(m.UntrustedSSIDs, u.SSID) {
			env.A = u
		}
		if env.B == nil && u.SSID == "" && m.isTether(u) {
			env.B = u
		}
	}
	return env, nil
}

func (m Matcher) isTether(u *Uplink) bool {
	if slices.Contains(m.TetherDrivers, u.Driver) {
		return true
	}
	for _, pat := range m.TetherNames {
		if ok, _ := filepath.Match(pat, u.Name); ok {
			return true
		}
	}
	return false
}

// returns every interface holding a main-table default route.
func uplinks(ignoreProto int) ([]*Uplink, error) {
	byIndex := map[int]*Uplink{}
	var order []*Uplink
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE)
		if err != nil {
			return nil, err
		}
		for _, r := range routes {
			if !isDefault(r) || r.Type != unix.RTN_UNICAST || r.LinkIndex == 0 || r.Gw == nil || int(r.Protocol) == ignoreProto {
				continue
			}
			u := byIndex[r.LinkIndex]
			if u == nil {
				l, err := netlink.LinkByIndex(r.LinkIndex)
				if err != nil {
					continue
				}
				attrs := l.Attrs()
				u = &Uplink{
					Name:   attrs.Name,
					Index:  attrs.Index,
					MAC:    attrs.HardwareAddr,
					Ether:  attrs.EncapType == "ether",
					Driver: driver(attrs.Name),
					metric: r.Priority,
				}
				byIndex[r.LinkIndex] = u
				order = append(order, u)
			}
			u.metric = min(u.metric, r.Priority)
			gw, _ := netip.AddrFromSlice(r.Gw)
			src, _ := netip.AddrFromSlice(r.Src)
			if family == netlink.FAMILY_V4 && !u.Gw4.IsValid() {
				u.Gw4, u.Addr4 = gw.Unmap(), src.Unmap()
			} else if family == netlink.FAMILY_V6 && !u.Gw6.IsValid() {
				u.Gw6, u.Addr6 = gw, src
			}
		}
	}
	for _, u := range order {
		fillAddrs(u)
	}
	return order, nil
}

func isDefault(r netlink.Route) bool {
	if r.Dst == nil {
		return true
	}
	ones, _ := r.Dst.Mask.Size()
	return ones == 0
}

// picks a usable global source address where the route had none.
func fillAddrs(u *Uplink) {
	addrs, err := netlink.AddrList(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: u.Index}}, netlink.FAMILY_ALL)
	if err != nil {
		return
	}
	for _, a := range addrs {
		ip, ok := netip.AddrFromSlice(a.IP)
		if !ok || a.Scope != unix.RT_SCOPE_UNIVERSE || a.Flags&(unix.IFA_F_TENTATIVE|unix.IFA_F_DEPRECATED|unix.IFA_F_DADFAILED) != 0 {
			continue
		}
		ip = ip.Unmap()
		switch {
		case ip.Is4() && !u.Addr4.IsValid():
			u.Addr4 = ip
		case ip.Is6() && !u.Addr6.IsValid() && u.Gw6.IsValid():
			u.Addr6 = ip
		}
	}
	if !u.Gw4.IsValid() {
		u.Addr4 = netip.Addr{}
	}
}

// returns the kernel driver bound to the interface's device, if any.
func driver(name string) string {
	p, err := os.Readlink(filepath.Join("/sys/class/net", name, "device/driver"))
	if err != nil {
		return ""
	}
	return filepath.Base(p)
}

// maps interface index to the SSID it is associated with.
func wifiSSIDs() map[int]string {
	out := map[int]string{}
	c, err := wifi.New()
	if err != nil {
		return out
	}
	defer c.Close()
	ifis, err := c.Interfaces()
	if err != nil {
		return out
	}
	for _, ifi := range ifis {
		if ifi.Name == "" || ifi.Type != wifi.InterfaceTypeStation {
			continue
		}
		if bss, err := c.BSS(ifi); err == nil && bss.Status == wifi.BSSStatusAssociated {
			out[ifi.Index] = bss.SSID
		}
	}
	return out
}
