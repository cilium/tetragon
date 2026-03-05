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

	memset(event, 0, sizeof(*event));
	if (probe_read(&event->family, sizeof(event->family), _(&address->sa_family)) < 0)
		return;
	probe_read(event->sun_path, sizeof(event->sun_path), un->sun_path);

	/* Determine socket type and calculate path length:
	 * - Abstract sockets start with a null byte, so we skip it (start_idx=1)
	 *   and calculate length from the second byte onwards
	 * - Filesystem sockets start directly with the path (start_idx=0)
	 * - Path length is calculated up to the null terminator, or max length if none found
	 */
	event->is_abstract = (event->sun_path[0] == '\0');

	if (event->is_abstract) {
#pragma unroll
		for (int i = 1; i < UNIX_SOCKET_PATH_MAX; i++) {
			if (event->sun_path[i] == '\0') {
				event->path_len = i - 1;
				return;
			}
		}
		event->path_len = UNIX_SOCKET_PATH_MAX - 1;
	} else {
#pragma unroll
		for (int i = 0; i < UNIX_SOCKET_PATH_MAX; i++) {
			if (event->sun_path[i] == '\0') {
				event->path_len = i;
				return;
			}
		}
		event->path_len = UNIX_SOCKET_PATH_MAX;
	}
}
#endif // __SOCKADDR_UN_H__
