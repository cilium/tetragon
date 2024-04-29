// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __SOCK_H__
#define __SOCK_H__

#include "tuple.h"
#include "probe_read_kernel_or_user.h"

// The sockaddr field is specifically a __u64 to deter from trying to dereference it.
// If an application needs more fields from the sock then they should be added to
// sk_type and copied with set_event_from_sock().
struct sk_type {
	struct tuple_type tuple;
	__u64 sockaddr;
	__u32 mark;
	__u32 priority;
	__u16 type;
	__u8 state;
	__u8 pad[5];
};

/* set_event_from_sock(sock)
 *
 * Populate the event args with the sock info.
 */
static inline __attribute__((unused)) void
set_event_from_sock(struct sk_type *event, struct sock *sk, bool userspace)
{
	struct sock_common *common = (struct sock_common *)sk;

	event->sockaddr = (__u64)sk;

	probe_read_kernel_or_user(&event->tuple.family, sizeof(event->tuple.family),
				  _(&common->skc_family), userspace);
	probe_read_kernel_or_user(&event->state, sizeof(event->state),
				  _((const void *)&common->skc_state), userspace);
	probe_read_kernel_or_user(&event->type, sizeof(event->type), _(&sk->sk_type), userspace);
	probe_read_kernel_or_user(&event->tuple.protocol, sizeof(event->tuple.protocol),
				  _(&sk->sk_protocol), userspace);
	if (bpf_core_field_size(sk->sk_protocol) == 4) {
		// In the BTF, the protocol field in kernels <v5.6 is 8 bits of a u32.
		// As such, the easiest way to get the correct (8 bit) value is to read
		// it as a u16 and shift it by 1 byte.
		event->tuple.protocol = event->tuple.protocol >> 8;
	}
	probe_read_kernel_or_user(&event->mark, sizeof(event->mark), _(&sk->sk_mark), userspace);
	probe_read_kernel_or_user(&event->priority, sizeof(event->priority),
				  _(&sk->sk_priority), userspace);

	event->tuple.saddr[0] = 0;
	event->tuple.saddr[1] = 0;
	event->tuple.daddr[0] = 0;
	event->tuple.daddr[1] = 0;
	switch (event->tuple.family) {
	case AF_INET:
		probe_read_kernel_or_user(&event->tuple.saddr, IPV4LEN, _(&common->skc_rcv_saddr), userspace);
		probe_read_kernel_or_user(&event->tuple.daddr, IPV4LEN, _(&common->skc_daddr), userspace);
		break;
	case AF_INET6:
		probe_read_kernel_or_user(&event->tuple.saddr, IPV6LEN, _(&common->skc_v6_rcv_saddr), userspace);
		probe_read_kernel_or_user(&event->tuple.daddr, IPV6LEN, _(&common->skc_v6_daddr), userspace);
	}

	probe_read_kernel_or_user(&event->tuple.sport, sizeof(event->tuple.sport), _(&common->skc_num), userspace);
	probe_read_kernel_or_user(&event->tuple.dport, sizeof(event->tuple.dport), _(&common->skc_dport), userspace);
	event->tuple.dport = bpf_ntohs(event->tuple.dport);
}
#endif // __SOCK_H__
