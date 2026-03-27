// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __SOCKADDR_UN_H__
#define __SOCKADDR_UN_H__

#define UNIX_SOCKET_PATH_MAX 108

struct sockaddr_un_type {
	__u16 family;
	bool is_abstract;
	__u8 path_len;
	char sun_path[UNIX_SOCKET_PATH_MAX];
};

/* set_event_from_sockaddr_un(event, address)
 *
 * Populate the event args with the sock info.
 */
FUNC_INLINE void
set_event_from_sockaddr_un(struct sockaddr_un_type *event, struct sockaddr *address)
{
	struct sockaddr_un *un = (struct sockaddr_un *)address;
	char first = 0;
	const char *src_path = un->sun_path;
	__u32 max_len = UNIX_SOCKET_PATH_MAX;

	memset(event, 0, sizeof(*event));
	if (probe_read(&event->family, sizeof(event->family), _(&address->sa_family)) < 0)
		return;
	if (probe_read(&first, sizeof(first), src_path) < 0)
		return;
	event->is_abstract = (first == '\0');
	if (event->is_abstract) {
		src_path = un->sun_path + 1;
		max_len = UNIX_SOCKET_PATH_MAX - 1;
	}
	if (probe_read(event->sun_path, max_len, src_path) < 0)
		return;

		/* Set path_len: first '\0' index in event->sun_path, or max_len if none within max_len. */
#pragma unroll
	for (int i = 0; i < UNIX_SOCKET_PATH_MAX; i++) {
		if (i >= max_len) {
			event->path_len = max_len;
			return;
		}
		if (event->sun_path[i] == '\0') {
			event->path_len = i;
			return;
		}
	}
}
#endif // __SOCKADDR_UN_H__
