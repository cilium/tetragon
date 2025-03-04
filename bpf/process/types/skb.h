// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __SKB_H__
#define __SKB_H__

#include "tuple.h"

struct skb_type {
	struct tuple_type tuple;
	__u32 hash;
	__u32 len;
	__u32 priority;
	__u32 mark;
	__u32 secpath_len;
	__u32 secpath_olen;
};

/* The IPv6 specification states that the following headers are valid
 * after the fixed header (up to 1 of each, except Destination Options,
 * which is up to 2):
 * Hop-by-Hop Options (0)
 * Routing (43)
 * Fragment (44)
 * Authentication Header (51)
 * Destination Options (60)
 * Encapsulation Security Payload Header (50)
 * Mobilty Header (135)
 * UDP Header (IPPROTO_UDP)
 * TCP Header (IPPROTO_TCP)
 * ICMP6 (IPPROTO_ICMP6)
 *
 * We choose to ignore Encapsulating Security Payload (ESP) because
 * of complexity (future requirement), Mobility (n/a), Host Identity
 * Protocol (replaces IP addresses), Shim6 Protocol (n/a), and the
 * Reserved header types. If we come across one of these headers, we
 * will return 0 to indicate failure (and no transport header). Otherwise,
 * we will skip other headers and return the offset of the transport
 * payload.
 */

struct ipv6extension {
	u16 ip_off;
	u16 byte_len;
	u8 header_count;
	u8 curr;
	u8 next;
	u8 len;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct ipv6extension);
	__uint(max_entries, 1);
} tg_ipv6_ext_heap SEC(".maps");

FUNC_INLINE u8
get_ip6_protocol(u16 *payload_off, struct ipv6hdr *ip, u16 network_header_off,
		 void *skb_head)
{
	struct ipv6extension *e;
	int zero = 0;
	u8 header_count;

	e = map_lookup_elem(&tg_ipv6_ext_heap, &zero);
	if (!e)
		return 0;

	e->ip_off = network_header_off;
	e->curr = 255;
	e->len = 0;
	if (probe_read(&e->next, sizeof(e->next), _(&ip->nexthdr)) < 0)
		return 0;

// Maximum 7 valid extensions.
#pragma unroll
	for (header_count = 0; header_count < 7; header_count++) {
		// Correct the length parameter, depending on current extension.
		switch (e->curr) {
		case 255:
			// Fixed header.
			e->byte_len = sizeof(struct ipv6hdr);
			break;
		case 0:
		case 43:
		case 60:
			e->byte_len = (e->len * 8) + 8;
			break;
		case 44:
			e->byte_len = 8;
			break;
		case 51:
			e->byte_len = (e->len * 4) + 8;
			break;
		}

		// Move to next extension.
		e->ip_off += e->byte_len;
		// If next is transport (or an unhandled header, e.g. ESP or Mobility), return it and the optional offset.
		if (e->next != 0 && e->next != 43 && e->next != 44 && e->next != 51 && e->next != 60) {
			if (payload_off)
				*payload_off = e->ip_off;
			return e->next;
		}
		e->curr = e->next;
		// Read next header and current length.
		if (probe_read(&e->next, 2,
			       skb_head + e->ip_off) < 0) {
			return 0;
		}
	}
	// Not found transport header.
	return 0;
}

/* set_event_from_skb(skb)
 *
 * Populate the event args with the SKB 5-tuple when supported. Currently,
 * only supports IPv4 with TCP/UDP.
 */
FUNC_INLINE int
set_event_from_skb(struct skb_type *event, struct sk_buff *skb)
{
	unsigned char *skb_head = 0;
	u16 l3_off;
	typeof(skb->transport_header) l4_off;
	u8 protocol;

	probe_read(&skb_head, sizeof(skb_head), _(&skb->head));
	probe_read(&l3_off, sizeof(l3_off), _(&skb->network_header));

	struct iphdr *ip = (struct iphdr *)(skb_head + l3_off);
	u8 iphdr_byte0;
	probe_read(&iphdr_byte0, 1, _(ip));

	u8 ip_ver = iphdr_byte0 >> 4;
	if (ip_ver == 4) { // IPv4
		probe_read(&protocol, 1, _(&ip->protocol));
		event->tuple.protocol = protocol;
		event->tuple.family = AF_INET;
		event->tuple.saddr[0] = 0;
		event->tuple.saddr[1] = 0;
		event->tuple.daddr[0] = 0;
		event->tuple.daddr[1] = 0;
		probe_read(&event->tuple.saddr, IPV4LEN, _(&ip->saddr));
		probe_read(&event->tuple.daddr, IPV4LEN, _(&ip->daddr));
		probe_read(&l4_off, sizeof(l4_off), _(&skb->transport_header));
	} else if (ip_ver == 6) {
		struct ipv6hdr *ip6 = (struct ipv6hdr *)(skb_head + l3_off);

		protocol = get_ip6_protocol(&l4_off, ip6, l3_off, skb_head);
		event->tuple.protocol = protocol;
		event->tuple.family = AF_INET6;
		probe_read(&event->tuple.saddr, IPV6LEN, _(&ip6->saddr));
		probe_read(&event->tuple.daddr, IPV6LEN, _(&ip6->daddr));
	} else {
		// This is not IP, so we don't know how to parse further.
		return -22;
	}

	if (protocol == IPPROTO_TCP) { // TCP
		struct tcphdr *tcp =
			(struct tcphdr *)(skb_head + l4_off);
		probe_read(&event->tuple.sport, sizeof(event->tuple.sport),
			   _(&tcp->source));
		probe_read(&event->tuple.dport, sizeof(event->tuple.dport),
			   _(&tcp->dest));
	} else if (protocol == IPPROTO_UDP) { // UDP
		struct udphdr *udp =
			(struct udphdr *)(skb_head + l4_off);
		probe_read(&event->tuple.sport, sizeof(event->tuple.sport),
			   _(&udp->source));
		probe_read(&event->tuple.dport, sizeof(event->tuple.dport),
			   _(&udp->dest));
	} else {
		event->tuple.sport = 0;
		event->tuple.dport = 0;
	}
	event->tuple.sport = bpf_ntohs(event->tuple.sport);
	event->tuple.dport = bpf_ntohs(event->tuple.dport);

	if (bpf_core_field_exists(skb->active_extensions)) {
		struct sec_path *sp;
		struct skb_ext *ext;
		u64 offset;
		int sec_path_id;

		if (!bpf_core_enum_value_exists(enum skb_ext_id,
						SKB_EXT_SEC_PATH))
			return 0;
		sec_path_id = bpf_core_enum_value(enum skb_ext_id,
						  SKB_EXT_SEC_PATH);

		bpf_core_read(&ext, sizeof(ext), &skb->extensions);
		if (ext) {
			bpf_core_read(&offset, sizeof(offset),
				      &ext->offset[sec_path_id]);
			sp = (void *)ext + (offset << 3);
			bpf_core_read(&event->secpath_len,
				      sizeof(event->secpath_len), &sp->len);
			bpf_core_read(&event->secpath_olen,
				      sizeof(event->secpath_olen), &sp->olen);
		}
	}

	return 0;
}
#endif // __SKB_H__
