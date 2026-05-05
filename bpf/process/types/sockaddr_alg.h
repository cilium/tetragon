// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __SOCKADDR_ALG_H__
#define __SOCKADDR_ALG_H__

struct sockaddr_alg_type {
	__u16 family;
	char type[14];
	__u32 feat;
	__u32 mask;
	char name[256];
	__u32 type_len;
	__u32 name_len;
};

/* set_event_from_sockaddr_alg(event, address)
 *
 * Populate the event args with the sock info.
 */
FUNC_INLINE void
set_event_from_sockaddr_alg(struct sockaddr_alg_type *event, struct sockaddr *address)
{
	struct sockaddr_alg_new *alg;
	int ret;

	if (!bpf_core_type_exists(struct sockaddr_alg_new))
		return;

	alg = (struct sockaddr_alg_new *)address;
	if (probe_read(&event->family, sizeof(event->family), _(&alg->salg_family)) < 0)
		return;
	ret = probe_read_str(&event->type, sizeof(event->type), _(&alg->salg_type));
	if (ret > 0)
		event->type_len = ret - 1;
	else
		return;
	if (probe_read(&event->feat, sizeof(event->feat), _(&alg->salg_feat)) < 0)
		return;
	if (probe_read(&event->mask, sizeof(event->mask), _(&alg->salg_mask)) < 0)
		return;
	ret = probe_read_str(&event->name, sizeof(event->name), _(&alg->salg_name));
	if (ret > 0)
		event->name_len = ret - 1;
}
#endif // __SOCKADDR_ALG_H__
