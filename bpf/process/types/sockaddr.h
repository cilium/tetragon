// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __SOCKADDR_H__
#define __SOCKADDR_H__

#include "tuple.h"

struct sockaddr_in_type {
	__u16 sin_family;
	__u16 sin_port;
	__u32 pad;
	__u64 sin_addr[2];
};

/* set_event_from_sockaddr_in(event, address)
 *
 * Populate the event args with the sock info.
 */
FUNC_INLINE void
set_event_from_sockaddr_in(struct sockaddr_in_type *event, struct sockaddr *address)
{
	struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)address;
	struct sockaddr_in *ipv4 = (struct sockaddr_in *)address;
	__u32 addr;

	memset(event, 0, sizeof(*event));
	if (probe_read(&event->sin_family, sizeof(event->sin_family), _(&address->sa_family)) < 0)
		return;
	switch (event->sin_family) {
	case AF_INET:
		// Read the 32 bit address into temporary var and then copy so we don't have to
		// consider endianness and alignment.
		probe_read(&addr, sizeof(addr), _(&ipv4->sin_addr));
		event->sin_addr[0] = addr;
		probe_read(&event->sin_port, sizeof(event->sin_port), _(&ipv4->sin_port));
		break;
	case AF_INET6:
		probe_read(&event->sin_addr, sizeof(event->sin_addr), _(&ipv6->sin6_addr));
		probe_read(&event->sin_port, sizeof(event->sin_port), _(&ipv6->sin6_port));
		break;
	}

	event->sin_port = bpf_ntohs(event->sin_port);
}
#endif // __SOCKADDR_H__
