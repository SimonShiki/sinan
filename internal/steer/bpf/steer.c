// SPDX-License-Identifier: GPL-2.0
//go:build ignore

// Steering of proxy-endpoint traffic away from the untrusted uplink (A).
//
// egress  (attached to A): packets to a proxy endpoint are SNAT'd to B's
//                          address and redirected out of B; dropped when B
//                          cannot carry them.
// ingress (attached to B): replies of steered flows are un-NAT'd and
//                          re-injected as if received on A, so sockets bound
//                          to A (e.g. by a proxy client) still match them.
//
// IPv4 addresses are handled as IPv4-mapped IPv6 (::ffff:a.b.c.d) throughout.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <stddef.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define AF_INET 2
#define AF_INET6 10

char LICENSE[] SEC("license") = "GPL";

enum verdict {
	VERDICT_PASS = 0,
	VERDICT_PROXY = 1,
};

struct lpm_key {
	__u32 prefixlen;
	__u8 addr[16];
};

struct cfg {
	__u32 a_ifindex;
	__u32 b_ifindex; // 0: B absent, drop everything that would be steered
	__u8 a_mac[6];
	__u8 has4; // B can carry IPv4
	__u8 has6; // B can carry IPv6
	__be32 gw4;
	__u8 b4[16];
	__u8 b6[16];
	__u8 gw6[16];
};

struct flow_key {
	__u8 raddr[16];
	__be16 rport;
	__be16 lport;
	__u8 proto;
	__u8 pad[3];
};

struct flow_val {
	__u8 laddr[16]; // original source address on A
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 65536);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm_key);
	__type(value, __u8);
} endpoints SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct cfg);
} config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct flow_key);
	__type(value, struct flow_val);
} flows SEC(".maps");

struct pkt {
	__u8 src[16];
	__u8 dst[16];
	__u32 l4; // offset of the L4 header
	__be16 sport;
	__be16 dport;
	__u8 proto;
	__u8 v6;
};

static __always_inline int eq16(const __u8 *a, const __u8 *b)
{
#pragma unroll
	for (int i = 0; i < 16; i++)
		if (a[i] != b[i])
			return 0;
	return 1;
}

// parse returns -1 for non-IP, 0 for IP without usable ports (other L4
// protocols, fragments, IPv6 extension headers) and 1 for TCP/UDP.
static __always_inline int parse(struct __sk_buff *skb, struct pkt *p)
{
	__builtin_memset(p, 0, sizeof(*p));
	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		struct iphdr ip;
		if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip, sizeof(ip)))
			return -1;
		p->src[10] = p->src[11] = p->dst[10] = p->dst[11] = 0xff;
		__builtin_memcpy(&p->src[12], &ip.saddr, 4);
		__builtin_memcpy(&p->dst[12], &ip.daddr, 4);
		p->proto = ip.protocol;
		p->l4 = ETH_HLEN + ip.ihl * 4;
		if (ip.frag_off & bpf_htons(0x3fff))
			return 0;
	} else if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr ip6;
		if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip6, sizeof(ip6)))
			return -1;
		__builtin_memcpy(p->src, &ip6.saddr, 16);
		__builtin_memcpy(p->dst, &ip6.daddr, 16);
		p->proto = ip6.nexthdr;
		p->l4 = ETH_HLEN + sizeof(ip6);
		p->v6 = 1;
	} else {
		return -1;
	}
	if (p->proto != IPPROTO_TCP && p->proto != IPPROTO_UDP)
		return 0;
	__be16 ports[2];
	if (bpf_skb_load_bytes(skb, p->l4, ports, sizeof(ports)))
		return 0;
	p->sport = ports[0];
	p->dport = ports[1];
	return 1;
}

// rewrite replaces the source (is_src) or destination address and fixes the
// L3/L4 checksums.
static __always_inline int rewrite(struct __sk_buff *skb, struct pkt *p, int is_src,
				   const __u8 *from, const __u8 *to)
{
	__u32 csum = p->l4 + (p->proto == IPPROTO_TCP ? 16 : 6);
	__u64 flags = BPF_F_PSEUDO_HDR | (p->proto == IPPROTO_UDP ? BPF_F_MARK_MANGLED_0 : 0);

	if (!p->v6) {
		__u32 off = ETH_HLEN + (is_src ? offsetof(struct iphdr, saddr) : offsetof(struct iphdr, daddr));
		__be32 o, n;
		__builtin_memcpy(&o, from + 12, 4);
		__builtin_memcpy(&n, to + 12, 4);
		if (bpf_l4_csum_replace(skb, csum, o, n, flags | sizeof(n)))
			return -1;
		if (bpf_l3_csum_replace(skb, ETH_HLEN + offsetof(struct iphdr, check), o, n, sizeof(n)))
			return -1;
		return bpf_skb_store_bytes(skb, off, &n, sizeof(n), 0);
	}

	__u32 off = ETH_HLEN + (is_src ? offsetof(struct ipv6hdr, saddr) : offsetof(struct ipv6hdr, daddr));
	__s64 diff = bpf_csum_diff((__be32 *)from, 16, (__be32 *)to, 16, 0);
	if (bpf_l4_csum_replace(skb, csum, 0, diff, flags))
		return -1;
	return bpf_skb_store_bytes(skb, off, to, 16, 0);
}

SEC("tc")
int sinan_egress(struct __sk_buff *skb)
{
	struct pkt p;
	int ok = parse(skb, &p);
	if (ok < 0)
		return TC_ACT_UNSPEC;

	struct lpm_key key = {.prefixlen = 128};
	__builtin_memcpy(key.addr, p.dst, 16);
	__u8 *v = bpf_map_lookup_elem(&endpoints, &key);
	if (!v || *v != VERDICT_PROXY)
		return TC_ACT_UNSPEC;

	// From here on the packet must never leave through A.
	__u32 zero = 0;
	struct cfg *c = bpf_map_lookup_elem(&config, &zero);
	if (!c || !c->b_ifindex || !ok || !(p.v6 ? c->has6 : c->has4))
		return TC_ACT_SHOT;

	struct flow_key fk = {.rport = p.dport, .lport = p.sport, .proto = p.proto};
	__builtin_memcpy(fk.raddr, p.dst, 16);
	struct flow_val *cur = bpf_map_lookup_elem(&flows, &fk);
	if (!cur || !eq16(cur->laddr, p.src)) {
		struct flow_val fv;
		__builtin_memcpy(fv.laddr, p.src, 16);
		bpf_map_update_elem(&flows, &fk, &fv, BPF_ANY);
	}

	if (rewrite(skb, &p, 1, p.src, p.v6 ? c->b6 : c->b4))
		return TC_ACT_SHOT;

	struct bpf_redir_neigh nh = {};
	if (p.v6) {
		nh.nh_family = AF_INET6;
		__builtin_memcpy(nh.ipv6_nh, c->gw6, 16);
	} else {
		nh.nh_family = AF_INET;
		nh.ipv4_nh = c->gw4;
	}
	return bpf_redirect_neigh(c->b_ifindex, &nh, sizeof(nh), 0);
}

SEC("tc")
int sinan_ingress(struct __sk_buff *skb)
{
	struct pkt p;
	if (parse(skb, &p) != 1)
		return TC_ACT_UNSPEC;

	struct flow_key fk = {.rport = p.sport, .lport = p.dport, .proto = p.proto};
	__builtin_memcpy(fk.raddr, p.src, 16);
	struct flow_val *fv = bpf_map_lookup_elem(&flows, &fk);
	if (!fv)
		return TC_ACT_UNSPEC;

	__u32 zero = 0;
	struct cfg *c = bpf_map_lookup_elem(&config, &zero);
	if (!c || !c->a_ifindex || !eq16(p.dst, p.v6 ? c->b6 : c->b4))
		return TC_ACT_UNSPEC;

	__u8 laddr[16];
	__builtin_memcpy(laddr, fv->laddr, 16);
	if (rewrite(skb, &p, 0, p.dst, laddr))
		return TC_ACT_SHOT;
	// Make A accept the frame as addressed to itself.
	if (bpf_skb_store_bytes(skb, 0, c->a_mac, 6, 0))
		return TC_ACT_SHOT;
	return bpf_redirect(c->a_ifindex, BPF_F_INGRESS);
}
