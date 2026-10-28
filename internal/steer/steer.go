// Package steer keeps proxy-endpoint traffic off the untrusted uplink with a
// pair of tc (TCX) eBPF programs; see bpf/steer.c.
package steer

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -type cfg -type lpm_key steer bpf/steer.c -- -O2 -Wall

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"github.com/SimonShiki/sinan/internal/netenv"
)

const (
	verdictPass  = 0
	verdictProxy = 1
)

// Steer owns the loaded programs, their maps and attachments.
type Steer struct {
	objs    steerObjects
	egress  attachment
	ingress attachment
	table   map[netip.Prefix]bool
}

type attachment struct {
	ifindex int
	link    link.Link
}

// Loads the programs into the kernel without attaching them.
func Load() (*Steer, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}
	s := &Steer{table: map[netip.Prefix]bool{}}
	if err := loadSteerObjects(&s.objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("verifier: %+v", ve)
		}
		return nil, err
	}
	return s, nil
}

// reports per family whether B can carry steered traffic.
func Capable(b *netenv.Uplink) (v4, v6 bool) {
	if b == nil || !b.Ether {
		return false, false
	}
	return b.Gw4.IsValid() && b.Addr4.IsValid(), b.Gw6.IsValid() && b.Addr6.IsValid()
}

// Installs the endpoint table and steers from a to b (b may be nil).
// The table is updated before attaching so A is never guarded by stale data.
func (s *Steer) Sync(a, b *netenv.Uplink, table map[netip.Prefix]bool) error {
	if !a.Ether {
		return fmt.Errorf("%s has no Ethernet framing", a.Name)
	}
	if err := s.syncTable(table); err != nil {
		return err
	}
	var c steerCfg
	c.A_ifindex = uint32(a.Index)
	copy(c.A_mac[:], a.MAC)
	has4, has6 := Capable(b)
	if has4 || has6 {
		c.B_ifindex = uint32(b.Index)
	}
	if has4 {
		c.Has4 = 1
		c.B4 = b.Addr4.As16()
		c.Gw4 = beUint32(b.Gw4)
	}
	if has6 {
		c.Has6 = 1
		c.B6 = b.Addr6.As16()
		c.Gw6 = b.Gw6.As16()
	}
	if err := s.objs.Config.Put(uint32(0), &c); err != nil {
		return fmt.Errorf("update config: %w", err)
	}
	if err := s.egress.set(a.Index, s.objs.SinanEgress, ebpf.AttachTCXEgress); err != nil {
		return fmt.Errorf("attach egress to %s: %w", a.Name, err)
	}
	bIndex := 0
	if c.B_ifindex != 0 {
		bIndex = b.Index
	}
	if err := s.ingress.set(bIndex, s.objs.SinanIngress, ebpf.AttachTCXIngress); err != nil {
		return fmt.Errorf("attach ingress to %s: %w", b.Name, err)
	}
	return nil
}

// Removes both programs from their interfaces.
func (s *Steer) Detach() {
	s.egress.set(0, nil, 0)
	s.ingress.set(0, nil, 0)
}

// Detaches and unloads everything.
func (s *Steer) Close() error {
	s.Detach()
	return s.objs.Close()
}

func (s *Steer) syncTable(want map[netip.Prefix]bool) error {
	for p, proxy := range want {
		if old, ok := s.table[p]; ok && old == proxy {
			continue
		}
		v := uint8(verdictPass)
		if proxy {
			v = verdictProxy
		}
		if err := s.objs.Endpoints.Put(lpmKey(p), v); err != nil {
			return fmt.Errorf("add endpoint %s: %w", p, err)
		}
		s.table[p] = proxy
	}
	for p := range s.table {
		if _, ok := want[p]; ok {
			continue
		}
		if err := s.objs.Endpoints.Delete(lpmKey(p)); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("remove endpoint %s: %w", p, err)
		}
		delete(s.table, p)
	}
	return nil
}

// (re)attaches prog to ifindex; ifindex 0 detaches.
func (a *attachment) set(ifindex int, prog *ebpf.Program, typ ebpf.AttachType) error {
	if a.link != nil && a.ifindex == ifindex {
		return nil
	}
	if a.link != nil {
		a.link.Close()
		a.link, a.ifindex = nil, 0
	}
	if ifindex == 0 {
		return nil
	}
	l, err := link.AttachTCX(link.TCXOptions{Interface: ifindex, Program: prog, Attach: typ})
	if err != nil {
		return err
	}
	a.link, a.ifindex = l, ifindex
	return nil
}

func lpmKey(p netip.Prefix) steerLpmKey {
	bits := p.Bits()
	if p.Addr().Is4() {
		bits += 96
	}
	return steerLpmKey{Prefixlen: uint32(bits), Addr: p.Addr().As16()}
}

// returns the address as a host-order integer holding network-order
// bytes, matching a __be32 field on little-endian BPF targets.
func beUint32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
