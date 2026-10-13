// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __TUPLE_H__
#define __TUPLE_H__

#define AF_INET	 2
#define AF_INET6 10
#define AF_UNIX	 1

#define IPV4LEN 4
#define IPV6LEN 16

struct tuple_type {
	__u64 saddr[2];
	__u64 daddr[2];
	__u16 sport;
	__u16 dport;
	__u16 protocol;
	__u16 family;
};

FUNC_INLINE void write_ipv6_addr_from_ipv4(u64 *dest, u32 src)
{
	dest[0] = src;
	dest[1] = 0;
}

FUNC_INLINE void write_ipv6_addr(u64 *dest, u64 *src)
{
	dest[0] = src[0];
	dest[1] = src[1];
}

FUNC_INLINE void write_ipv6_addr32(u32 *dest, u32 *src)
{
	dest[0] = src[0];
	dest[1] = src[1];
	dest[2] = src[2];
	dest[3] = src[3];
}

// ::ffff:x.x.x.x on little-endian: addr[0] is 0, low 32 bits of addr[1] are
// bytes 8-11.
FUNC_INLINE bool is_ipv4_mapped_ipv6(__u64 *addr)
{
	return addr[0] == 0 && (__u32)addr[1] == 0xffff0000;
}

// Bytes 12-15, kept in the host byte order used as the IPv4 LPM trie key.
FUNC_INLINE __u32 extract_ipv4_from_mapped(__u64 *addr)
{
	return (__u32)(addr[1] >> 32);
}

#endif // __TUPLE_H__
