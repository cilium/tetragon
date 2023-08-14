// SPDX-License-Identifier: GPL-2.0
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

/* set_event_from_skb(skb)
 *
 * Populate the event args with the SKB 5-tuple when supported. Currently,
 * only supports IPv4 with TCP/UDP.
 */
static inline __attribute__((unused)) int
set_event_from_skb(struct skb_type *event, struct sk_buff *skb)
{
	unsigned char *skb_head = 0;
	u16 l3_off;

	probe_read(&skb_head, sizeof(skb_head), _(&skb->head));
	probe_read(&l3_off, sizeof(l3_off), _(&skb->network_header));

	struct iphdr *ip = (struct iphdr *)(skb_head + l3_off);
	u8 iphdr_byte0;
	probe_read(&iphdr_byte0, 1, _(ip));

	u8 ip_ver = iphdr_byte0 >> 4;
	if (ip_ver == 4) { // IPv4
		u8 v4_prot;
		probe_read(&v4_prot, 1, _(&ip->protocol));

		event->tuple.protocol = v4_prot;

		event->tuple.family = AF_INET;

		probe_read(&event->tuple.saddr, sizeof(event->tuple.saddr), _(&ip->saddr));
		probe_read(&event->tuple.daddr, sizeof(event->tuple.daddr), _(&ip->daddr));
		typeof(skb->transport_header) l4_off;
		probe_read(&l4_off, sizeof(l4_off), _(&skb->transport_header));
		if (v4_prot == IPPROTO_TCP) { // TCP
			struct tcphdr *tcp =
				(struct tcphdr *)(skb_head + l4_off);
			probe_read(&event->tuple.sport, sizeof(event->tuple.sport),
				   _(&tcp->source));
			probe_read(&event->tuple.dport, sizeof(event->tuple.dport),
				   _(&tcp->dest));
		} else if (v4_prot == IPPROTO_UDP) { // UDP
			struct udphdr *udp =
				(struct udphdr *)(skb_head + l4_off);
			probe_read(&event->tuple.sport, sizeof(event->tuple.sport),
				   _(&udp->source));
			probe_read(&event->tuple.dport, sizeof(event->tuple.dport),
				   _(&udp->dest));
		}
		event->tuple.sport = bpf_ntohs(event->tuple.sport);
		event->tuple.dport = bpf_ntohs(event->tuple.dport);

		if (bpf_core_field_exists(skb->active_extensions)) {
			struct sec_path *sp;
			struct skb_ext *ext;
			u64 offset;

#define SKB_EXT_SEC_PATH 1 // TBD do this with BTF
			probe_read(&ext, sizeof(ext), _(&skb->extensions));
			if (ext) {
				probe_read(&offset, sizeof(offset),
					   _(&ext->offset[SKB_EXT_SEC_PATH]));
				sp = (void *)ext + (offset << 3);

				probe_read(&event->secpath_len,
					   sizeof(event->secpath_len),
					   _(&sp->len));
				probe_read(&event->secpath_olen,
					   sizeof(event->secpath_olen),
					   _(&sp->olen));
			}
		}
		return 0;
	} else if (ip_ver == 6) {
		return -1;
	}

	// This is not IP, so we don't know how to parse further.
	return -22;
}
#endif // __SKB_H__
