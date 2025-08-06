// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __SOCKADDR_UN_H__
#define __SOCKADDR_UN_H__

#define UNIX_PATH_MAX 108

struct sockaddr_un_type {
	__u16 family;
	char sun_path[UNIX_PATH_MAX];
};

/* set_event_from_sockaddr_un(event, address)
 *
 * Populate the event args with the sock info.
 */
FUNC_INLINE void
set_event_from_sockaddr_un(struct sockaddr_un_type *event, struct sockaddr *address)
{
	struct sockaddr_un *un = (struct sockaddr_un *)address;

	memset(event, 0, sizeof(*event));
	if (probe_read(&event->family, sizeof(event->family), _(&address->sa_family)) < 0)
		return;
	probe_read(event->sun_path, sizeof(event->sun_path), un->sun_path);
}
#endif // __SOCKADDR_UN_H__