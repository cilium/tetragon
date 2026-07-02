// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __DNS_H__
#define __DNS_H__

#define DNS_MAX_NAME	    255
#define DNS_HEADER_LEN	    12
/* RFC 1035 cap; EDNS0 is not supported in v1. */
#define DNS_UDP_PAYLOAD_MAX 512
#define DNS_MAX_LABEL	    63
#define DNS_WALK_MAX	    270

enum {
	dns_ok = 0,
	dns_err_short = -1,
	dns_err_not_query = -2,
	dns_err_opcode = -3,
	dns_err_qdcount = -4,
	dns_err_label = -5,
	dns_err_compression = -6,
	dns_err_truncated = -7,
	dns_err_iter = -8,
	dns_err_read = -9,
};

/* Keep in sync with MsgGenericKprobeDns in pkg/api/tracingapi/client_kprobe.go */
struct dns_type {
	__u16 tx_id;
	__u16 flags;
	__u16 qtype;
	__u16 qclass;
	__u8 qr;
	__u8 name_len;
	__u8 truncated;
	__u8 ok;
	char name[DNS_MAX_NAME + 1];
};

#ifdef __LARGE_BPF_PROG
struct dns_scratch {
	__u8 buf[DNS_UDP_PAYLOAD_MAX];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct dns_scratch);
} dns_scratch_map SEC(".maps");
#endif

FUNC_INLINE __u8 dns_to_lower(__u8 c)
{
	if (c >= 'A' && c <= 'Z')
		return c + ('a' - 'A');
	return c;
}

FUNC_INLINE int parse_dns_payload(const __u8 *buf, __u16 len, struct dns_type *ev)
{
	__u16 qdcount, pos, out_pos = 0;
	__u16 flags, txid;
	__u8 opcode;
	__u8 in_label = 0;
	__u8 remaining = 0;
	__u8 done = 0;
	__u16 i;

	if (len < DNS_HEADER_LEN)
		return dns_err_short;

	txid = ((__u16)buf[0] << 8) | buf[1];
	flags = ((__u16)buf[2] << 8) | buf[3];
	qdcount = ((__u16)buf[4] << 8) | buf[5];

	ev->tx_id = txid;
	ev->flags = flags;
	ev->qr = (flags >> 15) & 0x1;
	opcode = (flags >> 11) & 0xf;

	if (opcode != 0)
		return dns_err_opcode;
	if (qdcount < 1)
		return dns_err_qdcount;

	pos = DNS_HEADER_LEN;

	/* Single bounded loop (no nesting) keeps verifier complexity linear. */
#pragma unroll
	for (i = 0; i < DNS_WALK_MAX; i++) {
		__u8 b;

		if (done)
			break;
		if (pos >= len || pos >= DNS_UDP_PAYLOAD_MAX)
			return dns_err_short;

		b = buf[pos & (DNS_UDP_PAYLOAD_MAX - 1)];
		pos++;

		if (!in_label) {
			if (b == 0) {
				done = 1;
				continue;
			}
			/* RFC 1035 §4.1.4: top two bits 11 = compression pointer,
			 * illegal in the question section.
			 */
			if ((b & 0xc0) == 0xc0)
				return dns_err_compression;
			if (b > DNS_MAX_LABEL)
				return dns_err_label;
			if (out_pos > 0) {
				if (out_pos >= DNS_MAX_NAME) {
					ev->truncated = 1;
					return dns_err_truncated;
				}
				ev->name[out_pos & (DNS_MAX_NAME - 1)] = '.';
				out_pos++;
			}
			remaining = b;
			in_label = 1;
		} else {
			if (out_pos >= DNS_MAX_NAME) {
				ev->truncated = 1;
				return dns_err_truncated;
			}
			ev->name[out_pos & (DNS_MAX_NAME - 1)] = dns_to_lower(b);
			out_pos++;
			remaining--;
			if (remaining == 0)
				in_label = 0;
		}
	}

	if (!done)
		return dns_err_label;

	ev->name_len = (__u8)out_pos;
	if (out_pos <= DNS_MAX_NAME)
		ev->name[out_pos] = '\0';

	if (pos + 4 > len)
		return dns_err_short;
	ev->qtype = ((__u16)buf[pos & (DNS_UDP_PAYLOAD_MAX - 1)] << 8) |
		    buf[(pos + 1) & (DNS_UDP_PAYLOAD_MAX - 1)];
	ev->qclass = ((__u16)buf[(pos + 2) & (DNS_UDP_PAYLOAD_MAX - 1)] << 8) |
		     buf[(pos + 3) & (DNS_UDP_PAYLOAD_MAX - 1)];

	ev->ok = 1;
	return dns_ok;
}

#ifdef __LARGE_BPF_PROG
FUNC_INLINE int read_msghdr_payload(struct msghdr *msg, const char **out_buf,
				    size_t *out_len)
{
	long iter_iovec = -1, iter_ubuf __maybe_unused = -1;
	struct iov_iter *iter = _(&msg->msg_iter);
	struct kvec *kvec;
	const char *buf = NULL;
	size_t count = 0;
	u8 iter_type;
	void *tmp;

	if (!bpf_core_field_exists(iter->iter_type))
		return dns_err_iter;

	tmp = _(&iter->iter_type);
	if (probe_read(&iter_type, sizeof(iter_type), tmp) < 0)
		return dns_err_read;

	if (bpf_core_enum_value_exists(enum iter_type, ITER_IOVEC))
		iter_iovec = bpf_core_enum_value(enum iter_type, ITER_IOVEC);
#ifdef __V61_BPF_PROG
	if (bpf_core_enum_value_exists(enum iter_type, ITER_UBUF))
		iter_ubuf = bpf_core_enum_value(enum iter_type, ITER_UBUF);
#endif

	if (iter_type == iter_iovec) {
		tmp = _(&iter->kvec);
		if (probe_read(&kvec, sizeof(kvec), tmp) < 0)
			return dns_err_read;
		tmp = _(&kvec->iov_base);
		if (probe_read(&buf, sizeof(buf), tmp) < 0)
			return dns_err_read;
		tmp = _(&kvec->iov_len);
		if (probe_read(&count, sizeof(count), tmp) < 0)
			return dns_err_read;
	}
#ifdef __V61_BPF_PROG
	else if (iter_type == iter_ubuf) {
		tmp = _(&iter->ubuf);
		if (probe_read(&buf, sizeof(buf), tmp) < 0)
			return dns_err_read;
		tmp = _(&iter->count);
		if (probe_read(&count, sizeof(count), tmp) < 0)
			return dns_err_read;
	}
#endif
	else {
		return dns_err_iter;
	}

	if (!buf || count == 0)
		return dns_err_iter;

	*out_buf = buf;
	*out_len = count;
	return 0;
}

FUNC_INLINE void
set_event_from_msghdr(struct dns_type *ev, struct msghdr *msg)
{
	const char *iov_buf = NULL;
	size_t iov_len = 0;
	__u16 read_len;
	__u32 zero = 0;
	struct dns_scratch *scratch;

	memset(ev, 0, sizeof(*ev));

	scratch = map_lookup_elem(&dns_scratch_map, &zero);
	if (!scratch)
		return;

	if (read_msghdr_payload(msg, &iov_buf, &iov_len) < 0)
		return;

	read_len = iov_len > DNS_UDP_PAYLOAD_MAX ? DNS_UDP_PAYLOAD_MAX
						 : (__u16)iov_len;

	if (bpf_probe_read_user(scratch->buf, read_len, iov_buf) < 0)
		return;

	parse_dns_payload(scratch->buf, read_len, ev);
}
#else
FUNC_INLINE void
set_event_from_msghdr(struct dns_type *ev, struct msghdr *msg)
{
	memset(ev, 0, sizeof(*ev));
}
#endif

#endif /* __DNS_H__ */
