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

struct sockaddr_un_type {
	__u16 sin_family;
	char sun_path[108];
};

struct sockaddr_event {
	__u16 family;
	union {
		struct sockaddr_in_type in;
		struct sockaddr_un_type un;
	};
};

/* set_event_from_sockaddr(event, address)
 *
 * Populate the event args with the sock info.
 */
FUNC_INLINE void
set_event_from_sockaddr(struct sockaddr_event *event, struct sockaddr *address)
{
	struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)address;
	struct sockaddr_in *ipv4 = (struct sockaddr_in *)address;
	struct sockaddr_un *un = (struct sockaddr_un *)address;
	__u32 addr;

	memset(event, 0, sizeof(*event));
	if (probe_read(&event->family, sizeof(event->family), _(&address->sa_family)) < 0)
		return;
	switch (event->family) {
	case AF_INET:
		// Read the 32 bit address into temporary var and then copy so we don't have to
		// consider endianness and alignment.
		probe_read(&addr, sizeof(addr), _(&ipv4->sin_addr));
		event->in.sin_addr[0] = addr;
		probe_read(&event->in.sin_port, sizeof(event->in.sin_port), _(&ipv4->sin_port));
		break;
	case AF_INET6:
		probe_read(&event->in.sin_addr, sizeof(event->in.sin_addr), _(&ipv6->sin6_addr));
		probe_read(&event->in.sin_port, sizeof(event->in.sin_port), _(&ipv6->sin6_port));
		break;
	case AF_UNIX:
		probe_read_str(event->un.sun_path, sizeof(event->un.sun_path), un->sun_path);
		break;
	}

	if (event->family == AF_INET || event->family == AF_INET6)
		event->in.sin_port = bpf_ntohs(event->in.sin_port);
}
#endif // __SOCKADDR_H__
