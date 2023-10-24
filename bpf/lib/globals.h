// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef _GLOBALS__
#define _GLOBALS__
/* Global variables that are rewritten at program load time.
 *
 * These are special in that they're represented initially as
 * map value loads from the .rodata map, e.g. pointers to a map,
 * but we rewrite them into constant loads. This means they have
 * to be accessed using the address-of (&) operator and cannot be
 * dereferenced. Hence the wrapping into union to stop direct use.
 *
 * Example usage:
 *
 * GLOBAL_U32 g_foo;
 * ..
 * void func()
 * {
 *       ...
 *      uint32 foo = READ_GLOBAL(g_foo);
 * }
 */

#define GLOBAL_U16              \
	volatile const union {  \
		uint16_t __typ; \
		uint64_t __val; \
	}
#define GLOBAL_I16              \
	volatile const union {  \
		int16_t __typ;  \
		uint64_t __val; \
	}
#define GLOBAL_U32              \
	volatile const union {  \
		uint32_t __typ; \
		uint64_t __val; \
	}
#define GLOBAL_I32              \
	volatile const union {  \
		int32_t __typ;  \
		uint64_t __val; \
	}
#define GLOBAL_U64              \
	volatile const union {  \
		uint64_t __typ; \
		uint64_t __val; \
	}
#define GLOBAL_I64              \
	volatile const union {  \
		int64_t __typ;  \
		uint64_t __val; \
	}

/* Macro to read the value of a global variable declared using GLOBAL_XXX above. */
#define READ_GLOBAL(g)                                               \
	({                                                           \
		typeof((g).__typ) x =                                \
			(typeof((g).__typ))(uint64_t)(&((g).__val)); \
		x;                                                   \
	})
#endif
