/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright Authors of Tetragon */

#ifndef __TETRAGON_JVMTI_CLASSFILE_H__
#define __TETRAGON_JVMTI_CLASSFILE_H__

#include <stddef.h>
#include <stdint.h>

/*
 * Called for each method of the class that can be instrumented, name and
 * desc are the method name and its descriptor.
 *
 * Returns the number of calls to put into the method and stores allocated
 * array with the key for each call in keys, the array is released by the
 * caller of the callback. Returns 0 to keep the method unchanged and -1 to
 * keep the whole class unchanged.
 */
typedef int (*classfile_keys_fn)(void *ctx, const char *name, const char *desc, uint64_t **keys);

/*
 * Rewrite the class file in data, so its methods call TetragonHook.enter(key)
 * at entry for each key that keys_fn returns for the method. The ctx is
 * passed to keys_fn.
 *
 * Returns 1 with the allocated new class file in out, 0 if the class stays
 * unchanged, which is also the case when it can not be safely rewritten.
 */
int classfile_instrument(const unsigned char *data, size_t len, classfile_keys_fn keys_fn,
			 void *ctx, unsigned char **out, size_t *out_len);

#endif /* __TETRAGON_JVMTI_CLASSFILE_H__ */
