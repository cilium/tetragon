// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __TUPLE_H__
#define __TUPLE_H__

#define AF_INET	 2
#define AF_INET6 10

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

// Check if IPv6 address is IPv4-mapped (::ffff:x.x.x.x)
// IPv4-mapped format: first 80 bits are 0, next 16 bits are 0xffff, last 32 bits are IPv4
// In __u64[2] representation:
//   addr[0] = first 8 bytes (must be 0)
//   addr[1] = last 8 bytes (format depends on endianness)
//
// On little-endian systems (x86_64), IPv4-mapped ::ffff:192.0.2.1 looks like:
//   Bytes 0-7:  [0,0,0,0,0,0,0,0]              -> addr[0] = 0x0000000000000000
//   Bytes 8-15: [0,0,0xff,0xff,192,0,2,1]      -> addr[1] = 0x010200c0ffff0000
//                                                            (IPv4) (0xffff)
FUNC_INLINE bool is_ipv4_mapped_ipv6(__u64 *addr)
{
	// First 8 bytes must be all zeros
	if (addr[0] != 0)
		return false;

	// Next 2 bytes must be 0, then 2 bytes of 0xffff (in little-endian: lower 32 bits = 0xffff0000)
	// Mask out the IPv4 address (upper 32 bits) and check the pattern
	return (addr[1] & 0xffffffffULL) == 0xffff0000ULL;
}

// Extract IPv4 address from IPv4-mapped IPv6 address
// Returns the 32-bit IPv4 address from the last 4 bytes
// On little-endian: addr[1] has format 0xDDCCBBAA_FFFF0000, we want 0xAABBCCDD
FUNC_INLINE __u32 extract_ipv4_from_mapped(__u64 *addr)
{
	// IPv4 address is in the upper 32 bits of addr[1] on little-endian systems
	// Extract and byte-swap to get it in network byte order
	__u32 ipv4 = (__u32)(addr[1] >> 32);
	return ipv4;
}

#endif // __TUPLE_H__
