/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright Authors of Tetragon */

#define _GNU_SOURCE
#include <jni.h>
#include <jvmti.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include "proto.h"
#include "tetragonhook.h"

#define MAX_HOOKS 1024
#define MAX_METHODS 65536
#define MAX_CLASS_NAME 4096

typedef struct hook {
	uint32_t policy_id, hook_id;
	uint8_t kind;
	char *class_name;
	uint16_t nr_methods;

	struct {
		char *name;
		char *descriptor;
	} *methods;

	int committed;
	struct hook *next;
} hook;

typedef struct method_match {
	uint64_t key;
	uint32_t policy_id, hook_id;
	char *class_name, *name, *descriptor;
	int defined;
	struct method_match *next;
} method_match;

static JavaVM *g_vm;
static jvmtiEnv *g_jvmti;
static int g_sock = -1;
static int g_ring_fd = -1;
static void *g_ring_map = MAP_FAILED;
static size_t g_ring_len;
static struct tg_ring_hdr *g_ring;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_ring_lock = PTHREAD_MUTEX_INITIALIZER;
static hook *g_hooks;
static method_match *g_methods;
static uint64_t g_next_key = 1;

static uint64_t rd64(const unsigned char *p);

static uint16_t rd16(const unsigned char *p)
{
	return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t rd32(const unsigned char *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
	       ((uint32_t)p[3] << 24);
}

static void wr16(unsigned char *p, uint16_t v)
{
	p[0] = (unsigned char)v;
	p[1] = (unsigned char)(v >> 8);
}

static void wr32(unsigned char *p, uint32_t v)
{
	p[0] = (unsigned char)v;
	p[1] = (unsigned char)(v >> 8);
	p[2] = (unsigned char)(v >> 16);
	p[3] = (unsigned char)(v >> 24);
}

static void wr64(unsigned char *p, uint64_t v)
{
	for (int i = 0; i < 8; i++)
		p[i] = (unsigned char)(v >> (i * 8));
}

static int send_packet(uint16_t type, uint32_t seq, const void *payload,
		       size_t len)
{
	unsigned char *buf = calloc(1, sizeof(struct tg_msg_hdr) + len);
	if (!buf)
		return -1;
	wr16(buf, type);
	wr16(buf + 2, 0);
	wr32(buf + 4, seq);
	if (len)
		memcpy(buf + 8, payload, len);
	ssize_t n = send(g_sock, buf, 8 + len, MSG_NOSIGNAL);
	free(buf);
	return n == (ssize_t)(8 + len) ? 0 : -1;
}

static int receive_packet(unsigned char *buf, size_t cap, size_t *len,
			  int *passed_fd)
{
	struct iovec iov = {.iov_base = buf, .iov_len = cap};
	unsigned char control[CMSG_SPACE(sizeof(int))];
	struct msghdr msg = {.msg_iov = &iov,
			     .msg_iovlen = 1,
			     .msg_control = control,
			     .msg_controllen = sizeof(control)};
	ssize_t n = recvmsg(g_sock, &msg, 0);
	if (n < 8 || (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)))
		return -1;
	*len = (size_t)n;
	*passed_fd = -1;
	for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c;
	     c = CMSG_NXTHDR(&msg, c))
		if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS &&
		    c->cmsg_len >= CMSG_LEN(sizeof(int))) {
			memcpy(passed_fd, CMSG_DATA(c), sizeof(int));
			break;
		}
	return 0;
}

static void ring_notify(void)
{
	if (atomic_load_explicit((_Atomic uint32_t *)&g_ring->consumer_waiting,
				 memory_order_relaxed)) {
		atomic_fetch_add_explicit((_Atomic uint32_t *)&g_ring->notify,
					  1, memory_order_release);
		syscall(SYS_futex, &g_ring->notify, FUTEX_WAKE, 1, NULL, NULL,
			0);
	}
}

static int ring_write(uint32_t type, const void *payload, uint32_t payload_len)
{
	if (!g_ring)
		return -1;
	uint64_t data_size = g_ring->data_size;
	uint32_t length = (uint32_t)((sizeof(struct tg_rec_hdr) + payload_len +
				      TG_REC_ALIGN - 1) &
				     ~(TG_REC_ALIGN - 1));
	if (length > data_size)
		return -1;
	pthread_mutex_lock(&g_ring_lock);
	uint64_t prod = atomic_load_explicit(
	    (_Atomic uint64_t *)&g_ring->producer_pos, memory_order_relaxed);
	uint64_t cons = atomic_load_explicit(
	    (_Atomic uint64_t *)&g_ring->consumer_pos, memory_order_acquire);
	uint64_t off = prod & (data_size - 1), tail = data_size - off,
		 need = length + (tail < length ? tail : 0);
	if (prod - cons + need > data_size) {
		if (type == TG_REC_METHOD_ENTRY)
			atomic_fetch_add(&g_ring->dropped, 1);
		else if (type == TG_REC_METHOD_DEF)
			atomic_fetch_add(&g_ring->dropped_defs, 1);
		pthread_mutex_unlock(&g_ring_lock);
		return -1;
	}
	unsigned char *area = (unsigned char *)g_ring_map + TG_RING_HDR_SIZE;
	if (tail < length) {
		struct tg_rec_hdr *pad = (struct tg_rec_hdr *)(area + off);
		pad->len = 0;
		pad->type = TG_REC_PAD;
		memset((unsigned char *)pad + sizeof(*pad), 0,
		       tail - sizeof(*pad));
		atomic_store_explicit((_Atomic uint32_t *)&pad->len,
				      (uint32_t)tail, memory_order_release);
		prod += tail;
		off = 0;
	}
	struct tg_rec_hdr *hdr = (struct tg_rec_hdr *)(area + off);
	hdr->len = 0;
	hdr->type = type;
	if (payload_len)
		memcpy((unsigned char *)hdr + sizeof(*hdr), payload,
		       payload_len);
	memset((unsigned char *)hdr + sizeof(*hdr) + payload_len, 0,
	       length - sizeof(*hdr) - payload_len);
	atomic_store_explicit((_Atomic uint32_t *)&hdr->len, length,
			      memory_order_release);
	atomic_store_explicit((_Atomic uint64_t *)&g_ring->producer_pos,
			      prod + length, memory_order_release);
	pthread_mutex_unlock(&g_ring_lock);
	ring_notify();
	return 0;
}

static int emit_def(method_match *m)
{
	size_t cl = strlen(m->class_name), nl = strlen(m->name),
	       dl = strlen(m->descriptor);
	if (cl > 65535 || nl > 65535 || dl > 65535)
		return -1;
	unsigned char *p = calloc(1, 24 + cl + nl + dl);
	if (!p)
		return -1;
	wr64(p, m->key);
	wr32(p + 8, m->policy_id);
	wr32(p + 12, m->hook_id);
	wr16(p + 16, (uint16_t)cl);
	wr16(p + 18, (uint16_t)nl);
	wr16(p + 20, (uint16_t)dl);
	memcpy(p + 24, m->class_name, cl);
	memcpy(p + 24 + cl, m->name, nl);
	memcpy(p + 24 + cl + nl, m->descriptor, dl);
	int rc =
	    ring_write(TG_REC_METHOD_DEF, p, (uint32_t)(24 + cl + nl + dl));
	free(p);
	return rc;
}

static int eq(const char *a, const char *b)
{
	return a && b && strcmp(a, b) == 0;
}

static int method_allowed(hook *h, const char *name, const char *desc)
{
	if (h->nr_methods == 0)
		return 1;
	for (uint16_t i = 0; i < h->nr_methods; i++)
		if (eq(h->methods[i].name, name) &&
		    (!h->methods[i].descriptor[0] ||
		     eq(h->methods[i].descriptor, desc)))
			return 1;
	return 0;
}

static int class_allowed(hook *h, const char *name)
{
	if (h->kind == TG_HOOK_CLASS)
		return eq(h->class_name, name);
	size_t n = strlen(h->class_name);
	return strncmp(h->class_name, name, n) == 0;
}

static method_match *find_method(const char *class_name, const char *name,
				 const char *desc, uint32_t policy_id,
				 uint32_t hook_id)
{
	for (method_match *m = g_methods; m; m = m->next)
		if (m->policy_id == policy_id && m->hook_id == hook_id &&
		    eq(m->class_name, class_name) && eq(m->name, name) &&
		    eq(m->descriptor, desc))
			return m;
	return NULL;
}

static method_match *add_method(const char *class_name, const char *name,
				const char *desc, uint32_t policy_id,
				uint32_t hook_id)
{
	method_match *found =
	    find_method(class_name, name, desc, policy_id, hook_id);
	if (found)
		return found;
	method_match *m = calloc(1, sizeof(*m));
	if (!m)
		return NULL;
	m->key = g_next_key++;
	m->policy_id = policy_id;
	m->hook_id = hook_id;
	m->class_name = strdup(class_name);
	m->name = strdup(name);
	m->descriptor = strdup(desc);
	if (!m->class_name || !m->name || !m->descriptor) {
		free(m->class_name);
		free(m->name);
		free(m->descriptor);
		free(m);
		return NULL;
	}
	m->next = g_methods;
	g_methods = m;
	return m;
}

static char *get_string(const unsigned char *p, size_t len, size_t *off)
{
	if (*off + 2 > len)
		return NULL;
	uint16_t n = rd16(p + *off);
	*off += 2;
	if (n > len - *off)
		return NULL;
	char *s = calloc(1, (size_t)n + 1);
	if (!s)
		return NULL;
	memcpy(s, p + *off, n);
	*off += n;
	return s;
}

static void free_hook(hook *h)
{
	if (!h)
		return;
	free(h->class_name);
	for (uint16_t i = 0; i < h->nr_methods; i++) {
		free(h->methods[i].name);
		free(h->methods[i].descriptor);
	}
	free(h->methods);
	free(h);
}

static hook *parse_hook(const unsigned char *p, size_t len)
{
	if (len < 14)
		return NULL;
	hook *h = calloc(1, sizeof(*h));
	if (!h)
		return NULL;
	h->policy_id = rd32(p);
	h->hook_id = rd32(p + 4);
	h->kind = p[8];
	h->nr_methods = rd16(p + 10);
	size_t off = 12;
	if (h->kind != TG_HOOK_CLASS && h->kind != TG_HOOK_PREFIX)
		goto fail;
	h->class_name = get_string(p, len, &off);
	if (!h->class_name)
		goto fail;
	if (h->nr_methods) {
		h->methods = calloc(h->nr_methods, sizeof(*h->methods));
		if (!h->methods)
			goto fail;
	}
	for (uint16_t i = 0; i < h->nr_methods; i++) {
		h->methods[i].name = get_string(p, len, &off);
		h->methods[i].descriptor = get_string(p, len, &off);
		if (!h->methods[i].name || !h->methods[i].descriptor)
			goto fail;
	}
	if (off != len)
		goto fail;
	return h;
fail:
	free_hook(h);
	return NULL;
}

typedef struct {
	unsigned char *p;
	size_t n, cap;
} buffer;

typedef struct {
	uint8_t tag;
	const unsigned char *bytes;
	uint16_t len;
} cp_entry;

typedef struct call_plan {
	method_match *match;
	uint16_t long_index;
	struct call_plan *next;
} call_plan;

typedef struct {
	uint16_t name_index, desc_index;
	call_plan *calls;
	size_t count;
} method_plan;

static uint16_t be16(const unsigned char *p)
{
	return ((uint16_t)p[0] << 8) | p[1];
}

static uint32_t be32(const unsigned char *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | p[3];
}

static void put_be16(unsigned char *p, uint16_t v)
{
	p[0] = (unsigned char)(v >> 8);
	p[1] = (unsigned char)v;
}

static void put_be32(unsigned char *p, uint32_t v)
{
	p[0] = (unsigned char)(v >> 24);
	p[1] = (unsigned char)(v >> 16);
	p[2] = (unsigned char)(v >> 8);
	p[3] = (unsigned char)v;
}

static int append(buffer *b, const void *p, size_t n)
{
	if (n > SIZE_MAX - b->n)
		return -1;
	if (b->n + n > b->cap) {
		size_t cap = b->cap ? b->cap : 256;
		while (cap < b->n + n) {
			if (cap > SIZE_MAX / 2)
				return -1;
			cap *= 2;
		}
		unsigned char *q = realloc(b->p, cap);
		if (!q)
			return -1;
		b->p = q;
		b->cap = cap;
	}
	memcpy(b->p + b->n, p, n);
	b->n += n;
	return 0;
}

static int append_u2(buffer *b, uint16_t v)
{
	unsigned char p[2];
	put_be16(p, v);
	return append(b, p, 2);
}

static int append_u4(buffer *b, uint32_t v)
{
	unsigned char p[4];
	put_be32(p, v);
	return append(b, p, 4);
}

static int bounds(size_t off, size_t n, size_t total)
{
	return off <= total && n <= total - off;
}

static char *cp_string(cp_entry *cp, uint16_t idx)
{
	if (!cp[idx].tag || cp[idx].tag != 1)
		return NULL;
	char *s = calloc(1, (size_t)cp[idx].len + 1);
	if (!s)
		return NULL;
	memcpy(s, cp[idx].bytes, cp[idx].len);
	return s;
}

static int skip_member(const unsigned char *d, size_t len, size_t *off)
{
	if (!bounds(*off, 8, len))
		return -1;
	uint16_t attrs = be16(d + *off + 6);
	*off += 8;
	for (uint16_t i = 0; i < attrs; i++) {
		if (!bounds(*off, 6, len))
			return -1;
		uint32_t n = be32(d + *off + 2);
		*off += 6;
		if (!bounds(*off, n, len))
			return -1;
		*off += n;
	}
	return 0;
}

static int safe_bytecode(const unsigned char *code, uint32_t len)
{
	uint32_t pc = 0;
	while (pc < len) {
		uint8_t op = code[pc];
		uint32_t n = 1;
		if (op == 0xaa || op == 0xab) {
			uint32_t pad = (4 - ((pc + 1) & 3)) & 3;
			uint32_t base = pc + 1 + pad;
			if (!bounds(base, op == 0xaa ? 12 : 8, len))
				return 0;
			if (op == 0xaa) {
				int32_t low = (int32_t)be32(code + base + 4),
					high = (int32_t)be32(code + base + 8);
				if (high < low)
					return 0;
				uint64_t entries =
				    (uint64_t)((int64_t)high - low + 1);
				uint64_t size = 1 + pad + 12 + entries * 4;
				if (size > UINT32_MAX)
					return 0;
				n = (uint32_t)size;
			} else {
				int32_t pairs = (int32_t)be32(code + base + 4);
				if (pairs < 0)
					return 0;
				uint64_t size =
				    1 + pad + 8 + (uint64_t)pairs * 8;
				if (size > UINT32_MAX)
					return 0;
				n = (uint32_t)size;
			}
		}
		if (op == 0x10 || op == 0x12 || op == 0x15 || op == 0x16 ||
		    op == 0x17 || op == 0x18 || op == 0x19 || op == 0x36 ||
		    op == 0x37 || op == 0x38 || op == 0x39 || op == 0x3a ||
		    op == 0xa9 || op == 0xbc)
			n = 2;
		else if (op == 0x11 || op == 0x13 || op == 0x14 ||
			 (op >= 0x99 && op <= 0xa8) || op == 0x84 ||
			 (op >= 0xb2 && op <= 0xb8) ||
			 (op >= 0xbb && op <= 0xc1) || op == 0xc6 || op == 0xc7)
			n = 3;
		else if (op == 0xb9 || op == 0xba)
			n = 5;
		else if (op == 0xc5)
			n = 4;
		else if (op == 0xc8 || op == 0xc9)
			n = 5;
		else if (op == 0xc4) {
			if (pc + 1 >= len)
				return 0;
			n = code[pc + 1] == 0x84 ? 6 : 4;
		}
		if (!bounds(pc, n, len))
			return 0;
		pc += n;
	}
	return 1;
}

static int copy_verification_type(const unsigned char *src, size_t len,
				  size_t *off, uint32_t prefix, buffer *out)
{
	if (!bounds(*off, 1, len))
		return -1;
	uint8_t tag = src[(*off)++];
	append(out, &tag, 1);
	if (tag == 7) {
		if (!bounds(*off, 2, len))
			return -1;
		append(out, src + *off, 2);
		*off += 2;
	} else if (tag == 8) {
		if (!bounds(*off, 2, len))
			return -1;
		uint16_t pc = be16(src + *off);
		if (pc + prefix > 65535)
			return -1;
		append_u2(out, (uint16_t)(pc + prefix));
		*off += 2;
	} else if (tag > 8)
		return -1;
	return 0;
}

static int copy_element_value(const unsigned char *src, size_t len, size_t *off,
			      buffer *out);

static int copy_annotation(const unsigned char *src, size_t len, size_t *off,
			   buffer *out)
{
	if (!bounds(*off, 4, len))
		return -1;
	append(out, src + *off, 4);
	uint16_t pairs = be16(src + *off + 2);
	*off += 4;
	for (uint16_t i = 0; i < pairs; i++) {
		if (!bounds(*off, 2, len))
			return -1;
		append(out, src + *off, 2);
		*off += 2;
		if (copy_element_value(src, len, off, out))
			return -1;
	}
	return 0;
}

static int copy_element_value(const unsigned char *src, size_t len, size_t *off,
			      buffer *out)
{
	if (!bounds(*off, 1, len))
		return -1;
	uint8_t tag = src[*off];
	append(out, src + *off, 1);
	(*off)++;
	if (strchr("BCDFIJSZs", tag)) {
		if (!bounds(*off, 2, len))
			return -1;
		append(out, src + *off, 2);
		*off += 2;
		return 0;
	}
	if (tag == 'e') {
		if (!bounds(*off, 4, len))
			return -1;
		append(out, src + *off, 4);
		*off += 4;
		return 0;
	}
	if (tag == 'c') {
		if (!bounds(*off, 2, len))
			return -1;
		append(out, src + *off, 2);
		*off += 2;
		return 0;
	}
	if (tag == '@')
		return copy_annotation(src, len, off, out);
	if (tag == '[') {
		if (!bounds(*off, 2, len))
			return -1;
		uint16_t n = be16(src + *off);
		append(out, src + *off, 2);
		*off += 2;
		for (uint16_t i = 0; i < n; i++)
			if (copy_element_value(src, len, off, out))
				return -1;
		return 0;
	}
	return -1;
}

static int transform_type_annotations(const unsigned char *src, uint32_t len,
				      uint32_t prefix, buffer *out)
{
	if (len < 2)
		return -1;
	uint16_t count = be16(src);
	size_t off = 2;
	append_u2(out, count);
	for (uint16_t i = 0; i < count; i++) {
		if (!bounds(off, 1, len))
			return -1;
		uint8_t target = src[off++];
		append(out, &target, 1);
		if (target == 0x40 || target == 0x41) {
			if (!bounds(off, 2, len))
				return -1;
			uint16_t n = be16(src + off);
			append_u2(out, n);
			off += 2;
			for (uint16_t j = 0; j < n; j++) {
				if (!bounds(off, 6, len))
					return -1;
				uint16_t pc = be16(src + off);
				if (pc + prefix > 65535)
					return -1;
				append_u2(out, (uint16_t)(pc + prefix));
				append(out, src + off + 2, 4);
				off += 6;
			}
		} else if (target == 0x42) {
			if (!bounds(off, 2, len))
				return -1;
			append(out, src + off, 2);
			off += 2;
		} else if (target >= 0x43 && target <= 0x46) {
			if (!bounds(off, 2, len))
				return -1;
			uint16_t pc = be16(src + off);
			if (pc + prefix > 65535)
				return -1;
			append_u2(out, (uint16_t)(pc + prefix));
			off += 2;
		} else if (target >= 0x47 && target <= 0x4b) {
			if (!bounds(off, 3, len))
				return -1;
			uint16_t pc = be16(src + off);
			if (pc + prefix > 65535)
				return -1;
			append_u2(out, (uint16_t)(pc + prefix));
			append(out, src + off + 2, 1);
			off += 3;
		} else
			return -1;
		if (!bounds(off, 1, len))
			return -1;
		uint8_t path_len = src[off];
		size_t path_bytes = 1 + (size_t)path_len * 2;
		if (!bounds(off, path_bytes, len))
			return -1;
		append(out, src + off, path_bytes);
		off += path_bytes;
		if (copy_annotation(src, len, &off, out))
			return -1;
	}
	return off == len ? 0 : -1;
}

static int transform_stackmap(const unsigned char *src, uint32_t len,
			      uint32_t prefix, buffer *out)
{
	if (len < 2)
		return -1;
	uint16_t count = be16(src);
	size_t off = 2;
	append_u2(out, count);
	for (uint16_t i = 0; i < count; i++) {
		if (!bounds(off, 1, len))
			return -1;
		uint8_t ft = src[off++];
		uint16_t delta = 0, new_delta;
		if (ft <= 63) {
			delta = ft;
			new_delta = (uint16_t)(delta + (i == 0 ? prefix : 0));
			if ((uint32_t)delta + (i == 0 ? prefix : 0) > 65535)
				return -1;
			if (new_delta <= 63) {
				uint8_t n = (uint8_t)new_delta;
				append(out, &n, 1);
			} else {
				uint8_t n = 251;
				append(out, &n, 1);
				append_u2(out, new_delta);
			}
			continue;
		}
		if (ft <= 127 || ft == 247) {
			int compact = ft <= 127;
			delta = compact ? (uint16_t)(ft - 64)
					: (bounds(off, 2, len) ? be16(src + off)
							       : 0);
			if (!compact) {
				if (!bounds(off, 2, len))
					return -1;
				off += 2;
			}
			uint32_t d = (uint32_t)delta + (i == 0 ? prefix : 0);
			if (d > 65535)
				return -1;
			if (compact && d <= 63) {
				uint8_t n = (uint8_t)(64 + d);
				append(out, &n, 1);
			} else {
				uint8_t n = 247;
				append(out, &n, 1);
				append_u2(out, (uint16_t)d);
			}
			if (copy_verification_type(src, len, &off, prefix, out))
				return -1;
			continue;
		}
		if (ft >= 248 && ft <= 251) {
			if (!bounds(off, 2, len))
				return -1;
			delta = be16(src + off);
			off += 2;
			uint32_t d = (uint32_t)delta + (i == 0 ? prefix : 0);
			if (d > 65535)
				return -1;
			append(out, &ft, 1);
			append_u2(out, (uint16_t)d);
			continue;
		}
		if (ft >= 252 && ft <= 254) {
			if (!bounds(off, 2, len))
				return -1;
			delta = be16(src + off);
			off += 2;
			uint32_t d = (uint32_t)delta + (i == 0 ? prefix : 0);
			if (d > 65535)
				return -1;
			append(out, &ft, 1);
			append_u2(out, (uint16_t)d);
			for (uint8_t n = 0; n < (uint8_t)(ft - 251); n++)
				if (copy_verification_type(src, len, &off,
							   prefix, out))
					return -1;
			continue;
		}
		if (ft == 255) {
			if (!bounds(off, 2, len))
				return -1;
			delta = be16(src + off);
			off += 2;
			uint32_t d = (uint32_t)delta + (i == 0 ? prefix : 0);
			if (d > 65535)
				return -1;
			append(out, &ft, 1);
			append_u2(out, (uint16_t)d);
			if (!bounds(off, 2, len))
				return -1;
			uint16_t locals = be16(src + off);
			off += 2;
			append_u2(out, locals);
			for (uint16_t n = 0; n < locals; n++)
				if (copy_verification_type(src, len, &off,
							   prefix, out))
					return -1;
			if (!bounds(off, 2, len))
				return -1;
			uint16_t stack = be16(src + off);
			off += 2;
			append_u2(out, stack);
			for (uint16_t n = 0; n < stack; n++)
				if (copy_verification_type(src, len, &off,
							   prefix, out))
					return -1;
			continue;
		}
		return -1;
	}
	return off == len ? 0 : -1;
}

static int transform_code(const unsigned char *src, uint32_t src_len,
			  const unsigned char *prefix, uint32_t prefix_len,
			  cp_entry *cp, buffer *out)
{
	if (src_len < 12)
		return 0;
	uint16_t max_stack = be16(src), max_locals = be16(src + 2);
	uint32_t code_len = be32(src + 4);
	size_t off = 8;
	if (!bounds(off, code_len + 2, src_len) ||
	    code_len + prefix_len > 65535)
		return 0;
	const unsigned char *code = src + off;
	if (!safe_bytecode(code, code_len))
		return 0;
	off += code_len;
	uint16_t exceptions = be16(src + off);
	off += 2;
	if (!bounds(off, (size_t)exceptions * 8 + 2, src_len))
		return 0;
	const unsigned char *exception_table = src + off;
	off += (size_t)exceptions * 8;
	uint16_t attrs = be16(src + off);
	off += 2;
	buffer nested = {0};
	for (uint16_t i = 0; i < attrs; i++) {
		if (!bounds(off, 6, src_len))
			goto fail;
		uint16_t name_idx = be16(src + off);
		uint32_t n = be32(src + off + 2);
		off += 6;
		if (!bounds(off, n, src_len))
			goto fail;
		char *name = cp_string(cp, name_idx);
		if (!name)
			goto fail;
		if (strcmp(name, "LineNumberTable") == 0) {
			if (n < 2) {
				free(name);
				goto fail;
			}
			uint16_t count = be16(src + off);
			if (n != 2 + (uint32_t)count * 4) {
				free(name);
				goto fail;
			}
			buffer a = {0};
			append_u2(&a, count);
			for (uint16_t x = 0; x < count; x++) {
				uint16_t pc = be16(src + off + 2 + x * 4);
				if (pc + prefix_len > 65535) {
					free(a.p);
					free(name);
					goto fail;
				}
				append_u2(&a, (uint16_t)(pc + prefix_len));
				append(&a, src + off + 4 + x * 4, 2);
			}
			append_u2(&nested, name_idx);
			append_u4(&nested, (uint32_t)a.n);
			append(&nested, a.p, a.n);
			free(a.p);
		} else if (strcmp(name, "LocalVariableTable") == 0 ||
			   strcmp(name, "LocalVariableTypeTable") == 0) {
			if (n < 2) {
				free(name);
				goto fail;
			}
			uint16_t count = be16(src + off);
			if (n != 2 + (uint32_t)count * 10) {
				free(name);
				goto fail;
			}
			buffer a = {0};
			append_u2(&a, count);
			for (uint16_t x = 0; x < count; x++) {
				uint16_t pc = be16(src + off + 2 + x * 10);
				if (pc + prefix_len > 65535) {
					free(a.p);
					free(name);
					goto fail;
				}
				append_u2(&a, (uint16_t)(pc + prefix_len));
				append(&a, src + off + 4 + x * 10, 8);
			}
			append_u2(&nested, name_idx);
			append_u4(&nested, (uint32_t)a.n);
			append(&nested, a.p, a.n);
			free(a.p);
		} else if (strcmp(name, "StackMapTable") == 0) {
			buffer a = {0};
			if (transform_stackmap(src + off, n, prefix_len, &a) !=
			    0) {
				free(a.p);
				free(name);
				goto fail;
			}
			append_u2(&nested, name_idx);
			append_u4(&nested, (uint32_t)a.n);
			append(&nested, a.p, a.n);
			free(a.p);
		} else if (strcmp(name, "RuntimeVisibleTypeAnnotations") == 0 ||
			   strcmp(name, "RuntimeInvisibleTypeAnnotations") ==
			       0) {
			buffer a = {0};
			if (transform_type_annotations(src + off, n, prefix_len,
						       &a) != 0) {
				free(a.p);
				free(name);
				goto fail;
			}
			append_u2(&nested, name_idx);
			append_u4(&nested, (uint32_t)a.n);
			append(&nested, a.p, a.n);
			free(a.p);
		} else if (strcmp(name, "CharacterRangeTable") == 0) {
			if (n < 2) {
				free(name);
				goto fail;
			}
			uint16_t count = be16(src + off);
			if (n != 2 + (uint32_t)count * 14) {
				free(name);
				goto fail;
			}
			buffer a = {0};
			append_u2(&a, count);
			for (uint16_t x = 0; x < count; x++) {
				const unsigned char *e = src + off + 2 + x * 14;
				uint16_t start = be16(e), end = be16(e + 2);
				if (start + prefix_len > 65535 ||
				    end + prefix_len > 65535) {
					free(a.p);
					free(name);
					goto fail;
				}
				append_u2(&a, (uint16_t)(start + prefix_len));
				append_u2(&a, (uint16_t)(end + prefix_len));
				append(&a, e + 4, 10);
			}
			append_u2(&nested, name_idx);
			append_u4(&nested, (uint32_t)a.n);
			append(&nested, a.p, a.n);
			free(a.p);
		} else {
			free(name);
			goto fail;
		}
		free(name);
		off += n;
	}
	if (off != src_len)
		goto fail;
	append_u2(out, max_stack < 2 ? 2 : max_stack);
	append_u2(out, max_locals);
	append_u4(out, code_len + prefix_len);
	append(out, prefix, prefix_len);
	append(out, code, code_len);
	append_u2(out, exceptions);
	for (uint16_t i = 0; i < exceptions; i++) {
		const unsigned char *e = exception_table + i * 8;
		uint16_t start = be16(e), end = be16(e + 2),
			 handler = be16(e + 4);
		if (start + prefix_len > 65535 || end + prefix_len > 65535 ||
		    handler + prefix_len > 65535)
			goto fail;
		append_u2(out, (uint16_t)(start + prefix_len));
		append_u2(out, (uint16_t)(end + prefix_len));
		append_u2(out, (uint16_t)(handler + prefix_len));
		append(out, e + 6, 2);
	}
	append_u2(out, attrs);
	append(out, nested.p, nested.n);
	free(nested.p);
	return 1;
fail:
	free(nested.p);
	return 0;
}

/* The transformer deliberately declines Code attributes whose verifier or
 * bytecode offsets it cannot safely rewrite; the original class is preserved.
 */
static int transform_class(const char *class_name, const unsigned char *data,
			   size_t len, unsigned char **out, size_t *out_len)
{
	if (len < 10 || be32(data) != 0xcafebabe)
		return 0;
	uint16_t cp_count = be16(data + 8);
	cp_entry *cp = calloc(65536, sizeof(*cp));
	if (!cp)
		return -1;
	size_t off = 10;
	for (uint16_t i = 1; i < cp_count; i++) {
		if (!bounds(off, 1, len))
			goto bad;
		uint8_t tag = data[off++];
		cp[i].tag = tag;
		size_t n = 0;
		switch (tag) {
		case 1:
			if (!bounds(off, 2, len))
				goto bad;
			cp[i].len = be16(data + off);
			off += 2;
			if (!bounds(off, cp[i].len, len))
				goto bad;
			cp[i].bytes = data + off;
			off += cp[i].len;
			continue;
		case 3:
		case 4:
			n = 4;
			break;
		case 5:
		case 6:
			n = 8;
			break;
		case 7:
		case 8:
		case 16:
		case 19:
		case 20:
			n = 2;
			break;
		case 9:
		case 10:
		case 11:
		case 12:
		case 17:
		case 18:
			n = 4;
			break;
		case 15:
			n = 3;
			break;
		default:
			goto bad;
		}
		if (!bounds(off, n, len))
			goto bad;
		off += n;
		if (tag == 5 || tag == 6)
			i++;
	}
	size_t cp_end = off;
	if (!bounds(off, 8, len))
		goto bad;
	off += 6;
	uint16_t interfaces = be16(data + off);
	off += 2;
	if (!bounds(off, (size_t)interfaces * 2 + 2, len))
		goto bad;
	off += (size_t)interfaces * 2;
	uint16_t fields = be16(data + off);
	off += 2;
	for (uint16_t i = 0; i < fields; i++)
		if (skip_member(data, len, &off))
			goto bad;
	if (!bounds(off, 2, len))
		goto bad;
	size_t method_count_off = off;
	uint16_t method_count = be16(data + off);
	off += 2;
	method_plan *plans = calloc(method_count, sizeof(*plans));
	if (!plans)
		goto bad;
	method_match *old_head = g_methods;
	for (uint16_t i = 0; i < method_count; i++) {
		if (!bounds(off, 8, len))
			goto plan_bad;
		uint16_t access = be16(data + off),
			 name_idx = be16(data + off + 2),
			 desc_idx = be16(data + off + 4),
			 attrs = be16(data + off + 6);
		plans[i].name_index = name_idx;
		plans[i].desc_index = desc_idx;
		char *mn = cp_string(cp, name_idx),
		     *md = cp_string(cp, desc_idx);
		if (!mn || !md) {
			free(mn);
			free(md);
			goto plan_bad;
		}
		if (strcmp(mn, "<clinit>") != 0 &&
		    !(access & (0x0100 | 0x0400)))
			for (hook *h = g_hooks; h; h = h->next)
				if (h->committed &&
				    class_allowed(h, class_name) &&
				    method_allowed(h, mn, md)) {
					method_match *m = add_method(
					    class_name, mn, md, h->policy_id,
					    h->hook_id);
					if (!m) {
						free(mn);
						free(md);
						goto plan_bad;
					}
					call_plan *c = calloc(1, sizeof(*c));
					if (!c) {
						free(mn);
						free(md);
						goto plan_bad;
					}
					c->match = m;
					c->next = plans[i].calls;
					plans[i].calls = c;
					plans[i].count++;
				}
		free(mn);
		free(md);
		off += 8;
		for (uint16_t a = 0; a < attrs; a++) {
			if (!bounds(off, 6, len))
				goto plan_bad;
			uint32_t n = be32(data + off + 2);
			off += 6;
			if (!bounds(off, n, len))
				goto plan_bad;
			off += n;
		}
	}
	size_t methods_end = off;
	if (!bounds(off, 2, len))
		goto plan_bad;
	size_t calls = 0;
	for (uint16_t i = 0; i < method_count; i++)
		calls += plans[i].count;
	if (calls == 0) {
		free(plans);
		free(cp);
		return 0;
	}
	uint32_t new_cp_count = (uint32_t)cp_count + 6 + (uint32_t)calls * 2;
	if (new_cp_count > 65535)
		goto plan_bad;
	uint16_t class_utf = cp_count, class_idx = cp_count + 1,
		 enter_utf = cp_count + 2, desc_utf = cp_count + 3,
		 nt_idx = cp_count + 4, method_idx = cp_count + 5;
	uint32_t next_cp = (uint32_t)cp_count + 6;
	buffer cp_extra = {0};
	append(&cp_extra, "\1", 1);
	append_u2(&cp_extra, 24);
	append(&cp_extra, "io/tetragon/TetragonHook", 24);
	append(&cp_extra, "\7", 1);
	append_u2(&cp_extra, class_utf);
	append(&cp_extra, "\1", 1);
	append_u2(&cp_extra, 5);
	append(&cp_extra, "enter", 5);
	append(&cp_extra, "\1", 1);
	append_u2(&cp_extra, 4);
	append(&cp_extra, "(J)V", 4);
	append(&cp_extra, "\14", 1);
	append_u2(&cp_extra, enter_utf);
	append_u2(&cp_extra, desc_utf);
	append(&cp_extra, "\12", 1);
	append_u2(&cp_extra, class_idx);
	append_u2(&cp_extra, nt_idx);
	for (uint16_t i = 0; i < method_count; i++)
		for (call_plan *c = plans[i].calls; c; c = c->next) {
			c->long_index = (uint16_t)next_cp;
			unsigned char entry[9] = {5};
			uint64_t v = c->match->key;
			for (int b = 0; b < 8; b++)
				entry[8 - b] = (unsigned char)(v >> (8 * b));
			append(&cp_extra, entry, sizeof(entry));
			next_cp += 2;
		}
	buffer result = {0};
	append(&result, data, 10);
	put_be16(result.p + 8, (uint16_t)new_cp_count);
	append(&result, data + 10, cp_end - 10);
	append(&result, cp_extra.p, cp_extra.n);
	free(cp_extra.p);
	append(&result, data + cp_end, method_count_off + 2 - cp_end);
	off = method_count_off + 2;
	for (uint16_t i = 0; i < method_count; i++) {
		if (!bounds(off, 8, len))
			goto output_bad;
		size_t method_start = off;
		uint16_t attrs = be16(data + off + 6);
		off += 8;
		append(&result, data + method_start, 8);
		buffer prefix = {0};
		for (call_plan *c = plans[i].calls; c; c = c->next) {
			unsigned char seq[6] = {0x14, 0, 0, 0xb8, 0, 0};
			put_be16(seq + 1, c->long_index);
			put_be16(seq + 4, method_idx);
			append(&prefix, seq, sizeof(seq));
		}
		while (prefix.n % 4) {
			unsigned char nop = 0;
			append(&prefix, &nop, 1);
		}
		for (uint16_t a = 0; a < attrs; a++) {
			if (!bounds(off, 6, len))
				goto output_bad;
			uint16_t ni = be16(data + off);
			uint32_t n = be32(data + off + 2);
			size_t hdr = off;
			off += 6;
			if (!bounds(off, n, len))
				goto output_bad;
			char *attr_name = cp_string(cp, ni);
			if (!attr_name)
				goto output_bad;
			if (prefix.n && strcmp(attr_name, "Code") == 0) {
				buffer code = {0};
				int ok = transform_code(data + off, n, prefix.p,
							(uint32_t)prefix.n, cp,
							&code);
				if (!ok || code.n > UINT32_MAX) {
					free(attr_name);
					free(code.p);
					goto output_bad;
				}
				append(&result, data + hdr, 2);
				append_u4(&result, (uint32_t)code.n);
				append(&result, code.p, code.n);
				free(code.p);
			} else
				append(&result, data + hdr, 6 + n);
			free(attr_name);
			off += n;
		}
		free(prefix.p);
	}
	if (off != methods_end || !bounds(off, 2, len))
		goto output_bad;
	append(&result, data + off, len - off);
	for (uint16_t i = 0; i < method_count; i++)
		for (call_plan *c = plans[i].calls; c; c = c->next)
			if (!c->match->defined)
				c->match->defined = emit_def(c->match) == 0;
	for (uint16_t i = 0; i < method_count; i++) {
		call_plan *c = plans[i].calls;
		while (c) {
			call_plan *n = c->next;
			free(c);
			c = n;
		}
	}
	free(plans);
	free(cp);
	*out = result.p;
	*out_len = result.n;
	return 1;
output_bad:
	free(result.p);
plan_bad:
	while (g_methods != old_head) {
		method_match *m = g_methods;
		g_methods = m->next;
		free(m->class_name);
		free(m->name);
		free(m->descriptor);
		free(m);
	}
	if (plans) {
		for (uint16_t i = 0; i < method_count; i++) {
			call_plan *c = plans[i].calls;
			while (c) {
				call_plan *n = c->next;
				free(c);
				c = n;
			}
		}
		free(plans);
	}
bad:
	free(cp);
	return 0;
}

static void JNICALL hook_enter(JNIEnv *jni, jclass klass, jlong key)
{
	(void)jni;
	(void)klass;
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	uint64_t ktime =
	    (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
	uint32_t tid = (uint32_t)syscall(SYS_gettid);
	pthread_mutex_lock(&g_lock);
	for (method_match *m = g_methods; m; m = m->next)
		if (m->key == (uint64_t)key) {
			if (!m->defined)
				m->defined = emit_def(m) == 0;
			if (m->defined) {
				unsigned char p[24] = {0};
				wr64(p, m->key);
				wr64(p + 8, ktime);
				wr32(p + 16, tid);
				ring_write(TG_REC_METHOD_ENTRY, p, sizeof(p));
			}
			break;
		}
	pthread_mutex_unlock(&g_lock);
}

static int excluded_class(const char *name)
{
	return !name || strncmp(name, "java/", 5) == 0 ||
	       strncmp(name, "jdk/", 4) == 0 || strncmp(name, "sun/", 4) == 0 ||
	       strncmp(name, "io/tetragon/", 12) == 0;
}

static void JNICALL class_file_load_hook(jvmtiEnv *jvmti, JNIEnv *jni,
					 jclass redefining, jobject loader,
					 const char *name, jobject domain,
					 jint len, const unsigned char *bytes,
					 jint *new_len,
					 unsigned char **new_bytes)
{
	(void)jni;
	(void)redefining;
	(void)loader;
	(void)domain;
	if (len <= 0 || excluded_class(name))
		return;
	pthread_mutex_lock(&g_lock);
	unsigned char *transformed = NULL;
	size_t transformed_len = 0;
	int rc = transform_class(name, bytes, (size_t)len, &transformed,
				 &transformed_len);
	if (rc == 1 && transformed_len <= INT32_MAX &&
	    (*jvmti)->Allocate(jvmti, (jlong)transformed_len, new_bytes) ==
		JVMTI_ERROR_NONE) {
		memcpy(*new_bytes, transformed, transformed_len);
		*new_len = (jint)transformed_len;
	}
	pthread_mutex_unlock(&g_lock);
	free(transformed);
}

static void retransform_policy_classes(uint32_t policy_id,
				       int include_committed)
{
	jint count = 0;
	jclass *classes = NULL;
	if ((*g_jvmti)->GetLoadedClasses(g_jvmti, &count, &classes) !=
	    JVMTI_ERROR_NONE)
		return;
	for (jint i = 0; i < count; i++) {
		char *sig = NULL, *generic = NULL;
		(*g_jvmti)->GetClassSignature(g_jvmti, classes[i], &sig,
					      &generic);
		int selected = 0;
		if (sig && sig[0] == 'L') {
			size_t n = strlen(sig);
			char *name = calloc(1, n - 1);
			if (name) {
				memcpy(name, sig + 1, n - 2);
				pthread_mutex_lock(&g_lock);
				for (hook *h = g_hooks; h; h = h->next)
					if ((h->policy_id == policy_id ||
					     (include_committed &&
					      h->committed)) &&
					    class_allowed(h, name)) {
						selected = 1;
						break;
					}
				pthread_mutex_unlock(&g_lock);
				free(name);
			}
		}
		jboolean modifiable = JNI_FALSE;
		jvmtiError e = selected ? (*g_jvmti)->IsModifiableClass(
					      g_jvmti, classes[i], &modifiable)
					: JVMTI_ERROR_NONE;
		if (sig)
			(*g_jvmti)->Deallocate(g_jvmti, (unsigned char *)sig);
		if (generic)
			(*g_jvmti)->Deallocate(g_jvmti,
					       (unsigned char *)generic);
		if (!selected || e != JVMTI_ERROR_NONE || !modifiable)
			continue;
		e = (*g_jvmti)->RetransformClasses(g_jvmti, 1, &classes[i]);
		if (e != JVMTI_ERROR_NONE)
			fprintf(stderr,
				"tetragon-jvmti: class retransformation failed "
				"(%d)\n",
				e);
	}
	(*g_jvmti)->Deallocate(g_jvmti, (unsigned char *)classes);
}

static void cleanup_control_session(void)
{
	uint32_t *ids = NULL;
	size_t count = 0, capacity = 0;
	pthread_mutex_lock(&g_lock);
	for (hook *h = g_hooks; h; h = h->next) {
		h->committed = 0;
		int seen = 0;
		for (size_t i = 0; i < count; i++)
			if (ids[i] == h->policy_id) {
				seen = 1;
				break;
			}
		if (!seen) {
			if (count == capacity) {
				size_t next = capacity ? capacity * 2 : 8;
				uint32_t *p = realloc(ids, next * sizeof(*p));
				if (!p)
					break;
				ids = p;
				capacity = next;
			}
			ids[count++] = h->policy_id;
		}
	}
	pthread_mutex_unlock(&g_lock);
	for (size_t i = 0; i < count; i++)
		retransform_policy_classes(ids[i], 0);
	free(ids);
	pthread_mutex_lock(&g_lock);
	while (g_hooks) {
		hook *h = g_hooks;
		g_hooks = h->next;
		free_hook(h);
	}
	while (g_methods) {
		method_match *m = g_methods;
		g_methods = m->next;
		free(m->class_name);
		free(m->name);
		free(m->descriptor);
		free(m);
	}
	g_ring = NULL;
	void *ring_map = g_ring_map;
	size_t ring_len = g_ring_len;
	int ring_fd = g_ring_fd;
	g_ring_map = MAP_FAILED;
	g_ring_len = 0;
	g_ring_fd = -1;
	int fd = g_sock;
	g_sock = -1;
	pthread_mutex_unlock(&g_lock);
	if (fd >= 0)
		close(fd);
	if (ring_map != MAP_FAILED)
		munmap(ring_map, ring_len);
	if (ring_fd >= 0)
		close(ring_fd);
}

static int define_hook_class(JNIEnv *jni)
{
	jclass klass = (*jni)->FindClass(jni, "io/tetragon/TetragonHook");
	if (!klass) {
		(*jni)->ExceptionClear(jni);
		klass =
		    (*jni)->DefineClass(jni, "io/tetragon/TetragonHook", NULL,
					(const jbyte *)tetragon_hook_class,
					(jsize)sizeof(tetragon_hook_class));
	}
	if (!klass)
		return -1;
	JNINativeMethod method = {
	    .name = "enter", .signature = "(J)V", .fnPtr = (void *)hook_enter};
	return (*jni)->RegisterNatives(jni, klass, &method, 1) == JNI_OK ? 0
									 : -1;
}

static int ack(uint32_t seq, int32_t status, uint32_t classes,
	       const char *error)
{
	size_t n = error ? strlen(error) : 0;
	unsigned char p[12 + 256] = {0};
	if (n > 250)
		n = 250;
	wr32(p, seq);
	wr32(p + 4, (uint32_t)status);
	wr32(p + 8, classes);
	wr16(p + 12, (uint16_t)n);
	if (n)
		memcpy(p + 14, error, n);
	return send_packet(TG_MSG_ACK, seq, p, 14 + n);
}

static int handle_command(unsigned char *buf, size_t len)
{
	uint16_t type = rd16(buf);
	uint32_t seq = rd32(buf + 4);
	const unsigned char *p = buf + 8;
	size_t n = len - 8;
	int status = 0;
	if (type == TG_MSG_HOOK_ADD) {
		hook *h = parse_hook(p, n);
		if (!h)
			status = -1;
		else {
			pthread_mutex_lock(&g_lock);
			int duplicate = 0;
			for (hook *it = g_hooks; it; it = it->next)
				if (it->policy_id == h->policy_id &&
				    it->hook_id == h->hook_id) {
					duplicate = 1;
					break;
				}
			if (!duplicate) {
				h->next = g_hooks;
				g_hooks = h;
				h = NULL;
			}
			pthread_mutex_unlock(&g_lock);
			free_hook(h);
		}
	} else if (type == TG_MSG_POLICY_COMMIT && n == 4) {
		uint32_t id = rd32(p);
		pthread_mutex_lock(&g_lock);
		for (hook *h = g_hooks; h; h = h->next)
			if (h->policy_id == id)
				h->committed = 1;
		pthread_mutex_unlock(&g_lock);
		retransform_policy_classes(id, 0);
	} else if (type == TG_MSG_POLICY_REMOVE && n == 4) {
		uint32_t id = rd32(p);
		pthread_mutex_lock(&g_lock);
		for (hook *h = g_hooks; h; h = h->next)
			if (h->policy_id == id)
				h->committed = 0;
		pthread_mutex_unlock(&g_lock);
		retransform_policy_classes(id, 1);
		pthread_mutex_lock(&g_lock);
		hook **h = &g_hooks;
		while (*h) {
			if ((*h)->policy_id == id) {
				hook *old = *h;
				*h = old->next;
				free_hook(old);
			} else
				h = &(*h)->next;
		}
		method_match *removed = NULL;
		method_match **m = &g_methods;
		while (*m) {
			if ((*m)->policy_id == id) {
				method_match *old = *m;
				*m = old->next;
				old->next = removed;
				removed = old;
			} else
				m = &(*m)->next;
		}
		while (removed) {
			method_match *old = removed;
			removed = removed->next;
			free(old->class_name);
			free(old->name);
			free(old->descriptor);
			free(old);
		}
		pthread_mutex_unlock(&g_lock);
	} else
		status = -1;
	return ack(seq, status, 0,
		   status ? "invalid or unsupported command" : "");
}

static void *control_thread(void *unused)
{
	(void)unused;
	JNIEnv *jni = NULL;
	JavaVMAttachArgs args = {.version = JNI_VERSION_1_6,
				 .name = "tetragon-jvmti-control",
				 .group = NULL};
	if ((*g_vm)->AttachCurrentThreadAsDaemon(g_vm, (void **)&jni, &args) !=
	    JNI_OK)
		return NULL;
	unsigned char buf[TG_MSG_MAX_SIZE];
	for (;;) {
		size_t n = 0;
		int fd = -1;
		if (receive_packet(buf, sizeof(buf), &n, &fd) != 0)
			break;
		if (fd >= 0)
			close(fd);
		if (handle_command(buf, n) != 0)
			break;
	}
	cleanup_control_session();
	(*g_vm)->DetachCurrentThread(g_vm);
	return NULL;
}

static int connect_control(const char *path)
{
	if (!path ||
	    strlen(path) >= sizeof(((struct sockaddr_un *)0)->sun_path))
		return -1;
	int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;
	struct sockaddr_un addr = {.sun_family = AF_UNIX};
	strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
		close(fd);
		return -1;
	}
	return fd;
}

JNIEXPORT jint JNICALL Agent_OnAttach(JavaVM *vm, char *options, void *reserved)
{
	(void)reserved;
	if (!options || !options[0]) {
		fprintf(stderr, "tetragon-jvmti: no socket option\n");
		return JNI_ERR;
	}
	g_vm = vm;
	pthread_mutex_lock(&g_lock);
	int already_attached = g_sock >= 0;
	pthread_mutex_unlock(&g_lock);
	if (already_attached)
		return JNI_ERR;
	if ((*vm)->GetEnv(vm, (void **)&g_jvmti, JVMTI_VERSION_1_2) != JNI_OK ||
	    !g_jvmti) {
		fprintf(stderr, "tetragon-jvmti: GetEnv failed\n");
		return JNI_ERR;
	}
	int control_fd = connect_control(options);
	if (control_fd < 0) {
		fprintf(stderr, "tetragon-jvmti: connect failed for %s: %s\n",
			options, strerror(errno));
		return JNI_ERR;
	}
	pthread_mutex_lock(&g_lock);
	g_sock = control_fd;
	pthread_mutex_unlock(&g_lock);
	char *vm_version = NULL;
	(*g_jvmti)->GetSystemProperty(g_jvmti, "java.vm.version", &vm_version);
	size_t version_len = vm_version ? strlen(vm_version) : 0;
	if (version_len > 255)
		version_len = 255;
	unsigned char packet[8 + 4 + 2 + 255] = {0};
	wr16(packet, TG_MSG_HELLO);
	wr32(packet + 4, 0);
	wr32(packet + 8, TG_PROTO_VERSION);
	wr16(packet + 12, (uint16_t)version_len);
	if (version_len)
		memcpy(packet + 14, vm_version, version_len);
	if (vm_version)
		(*g_jvmti)->Deallocate(g_jvmti, (unsigned char *)vm_version);
	if (send(g_sock, packet, 14 + version_len, MSG_NOSIGNAL) !=
	    (ssize_t)(14 + version_len)) {
		fprintf(stderr, "tetragon-jvmti: HELLO send failed\n");
		return JNI_ERR;
	}
	unsigned char buf[TG_MSG_MAX_SIZE];
	size_t n = 0;
	int passed = -1;
	if (receive_packet(buf, sizeof(buf), &n, &passed) != 0 ||
	    rd16(buf) != TG_MSG_RING || n < 16 || passed < 0) {
		fprintf(stderr,
			"tetragon-jvmti: ring handoff failed n=%zu type=%u "
			"fd=%d errno=%s\n",
			n, n >= 2 ? rd16(buf) : 0, passed, strerror(errno));
		return JNI_ERR;
	}
	g_ring_len = (size_t)rd64(buf + 8);
	if (g_ring_len < TG_RING_HDR_SIZE + 1024) {
		fprintf(stderr, "tetragon-jvmti: invalid ring length %zu\n",
			g_ring_len);
		return JNI_ERR;
	}
	g_ring_fd = passed;
	g_ring_map = mmap(NULL, g_ring_len, PROT_READ | PROT_WRITE, MAP_SHARED,
			  g_ring_fd, 0);
	if (g_ring_map == MAP_FAILED) {
		fprintf(stderr, "tetragon-jvmti: mmap ring failed %s\n",
			strerror(errno));
		return JNI_ERR;
	}
	g_ring = (struct tg_ring_hdr *)g_ring_map;
	if (g_ring->magic != TG_RING_MAGIC ||
	    g_ring->version != TG_RING_VERSION ||
	    g_ring->data_size != g_ring_len - TG_RING_HDR_SIZE) {
		fprintf(stderr,
			"tetragon-jvmti: invalid ring header magic=%x "
			"version=%u size=%lu len=%zu\n",
			g_ring->magic, g_ring->version,
			(unsigned long)g_ring->data_size, g_ring_len);
		return JNI_ERR;
	}
	jvmtiCapabilities caps = {0};
	caps.can_generate_all_class_hook_events = 1;
	caps.can_retransform_classes = 1;
	jvmtiError jerr = (*g_jvmti)->AddCapabilities(g_jvmti, &caps);
	if (jerr != JVMTI_ERROR_NONE) {
		fprintf(stderr, "tetragon-jvmti: AddCapabilities failed %d\n",
			jerr);
		return JNI_ERR;
	}
	JNIEnv *jni = NULL;
	if ((*vm)->GetEnv(vm, (void **)&jni, JNI_VERSION_1_6) != JNI_OK ||
	    define_hook_class(jni) != 0) {
		fprintf(stderr, "tetragon-jvmti: failed to define TetragonHook "
				"bootstrap class\n");
		return JNI_ERR;
	}
	jvmtiEventCallbacks callbacks = {0};
	callbacks.ClassFileLoadHook = class_file_load_hook;
	jerr = (*g_jvmti)->SetEventCallbacks(g_jvmti, &callbacks,
					     sizeof(callbacks));
	if (jerr != JVMTI_ERROR_NONE) {
		fprintf(stderr, "tetragon-jvmti: SetEventCallbacks failed %d\n",
			jerr);
		return JNI_ERR;
	}
	jerr = (*g_jvmti)->SetEventNotificationMode(
	    g_jvmti, JVMTI_ENABLE, JVMTI_EVENT_CLASS_FILE_LOAD_HOOK, NULL);
	if (jerr != JVMTI_ERROR_NONE) {
		fprintf(stderr,
			"tetragon-jvmti: enable class load hook failed %d\n",
			jerr);
		return JNI_ERR;
	}
	pthread_t thread;
	int perr = pthread_create(&thread, NULL, control_thread, NULL);
	if (perr != 0) {
		fprintf(stderr,
			"tetragon-jvmti: control thread create failed %d\n",
			perr);
		return JNI_ERR;
	}
	pthread_detach(thread);
	return JNI_OK;
}

/* Decode u64 in the shared little-endian protocol. */
static uint64_t rd64(const unsigned char *p)
{
	uint64_t v = 0;
	for (int i = 0; i < 8; i++)
		v |= (uint64_t)p[i] << (i * 8);
	return v;
}
