// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Tetragon */

#ifndef __JAVA_H
#define __JAVA_H

#include "process.h"

#define JAVA_STRING_LEN 128
#define MSG_JAVA_SIZE 432

struct msg_java {
	struct msg_common common;
	struct msg_execve_key current;
	__u64 method_id;
	__u32 tid;
	char class_name[JAVA_STRING_LEN];
	char method_name[JAVA_STRING_LEN];
	char descriptor[JAVA_STRING_LEN];
	__u8 pad[4];
};

_Static_assert(sizeof(struct msg_java) == MSG_JAVA_SIZE, "msg_java size");
_Static_assert(__builtin_offsetof(struct msg_java, current) == 16, "msg_java current offset");
_Static_assert(__builtin_offsetof(struct msg_java, method_id) == 32, "msg_java method_id offset");
_Static_assert(__builtin_offsetof(struct msg_java, tid) == 40, "msg_java tid offset");
_Static_assert(__builtin_offsetof(struct msg_java, class_name) == 44, "msg_java class offset");
_Static_assert(__builtin_offsetof(struct msg_java, method_name) == 172, "msg_java method offset");
_Static_assert(__builtin_offsetof(struct msg_java, descriptor) == 300, "msg_java descriptor offset");
_Static_assert(__builtin_offsetof(struct msg_java, pad) == 428, "msg_java pad offset");

#endif /* __JAVA_H */
