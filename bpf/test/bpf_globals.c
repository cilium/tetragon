// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"

#include "hubble_msg.h"
#include "bpf_events.h"
#include "globals.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

GLOBAL_U16 g_u16;
GLOBAL_I16 g_i16;
GLOBAL_U32 g_u32;
GLOBAL_I32 g_i32;
GLOBAL_U64 g_u64;
GLOBAL_I64 g_i64;

__attribute__((section("socket_filter/read_globals_test"), used)) int
read_globals_test(void *ctx)
{
	if (READ_GLOBAL(g_u16) != 65535)
		return __LINE__;

	if (READ_GLOBAL(g_i16) != -32767)
		return __LINE__;

	if (READ_GLOBAL(g_u32) != 4294967295)
		return __LINE__;

	if (READ_GLOBAL(g_i32) != -2147483648)
		return __LINE__;

	if (READ_GLOBAL(g_u64) != 18446744073709551615ULL)
		return __LINE__;

	if (READ_GLOBAL(g_i64) != -9223372036854775808ULL)
		return __LINE__;

	return 0;
}
