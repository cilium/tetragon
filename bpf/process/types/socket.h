// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __SOCKET_H__
#define __SOCKET_H__

#include "tuple.h"
#include "sock.h"

/* set_event_from_socket(socket)
 *
 * Populate the event args with the sock info from the socket.
 */
FUNC_INLINE void
set_event_from_socket(struct sk_type *event, struct socket *sock)
{
	struct sock *sk;

	probe_read(&sk, sizeof(sk), _(&sock->sk));
	if (sk)
		set_event_from_sock(event, sk);
}
#endif // __SOCKET_H__
