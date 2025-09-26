// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Tetragon */

#ifndef GET_FILEID_H__
#define GET_FILEID_H__

FUNC_INLINE __u16
get_fileid__(const char *const fname)
{
#define fileid__(f, id)                  \
	if (!__builtin_strcmp(f, fname)) \
		return id;
#include "fileids.h"
#undef fileid__

	return 0;
}

#endif /* GET_FILEID_H__ */
