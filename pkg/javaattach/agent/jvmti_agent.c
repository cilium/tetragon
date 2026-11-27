// SPDX-License-Identifier: Apache-2.0
/* Copyright Authors of Tetragon */

/*
 * Native JVMTI agent that Tetragon loads into running HotSpot JVMs.
 *
 * The agent connects to Tetragon's control socket, receives hooks (classes
 * and methods to monitor) and rewrites matching classes so each monitored
 * method calls TetragonHook.enter(key) at its entry. The native enter()
 * reports the call to Tetragon through the shared ring buffer.
 *
 * The control channel and the ring formats are described in proto.h.
 *
 * Agent lifetime, time goes down:
 *
 *   Event           Tetragon <-> agent       Agent function and its actions
 *   -----           ------------------       ------------------------------
 *
 *   agent load      --------------------->   Agent_OnAttach
 *                                              connect to the control socket
 *                   <--- HELLO -----------     send JVM version
 *                   ---- ACK ------------>     session is open
 *                                              define TetragonHook class
 *                                              enable class load hook
 *                                              start control thread
 *
 *   ring setup      ---- RING + memfd --->   handle_ring
 *                                              map the ring
 *                   <--- ACK -------------
 *
 *   policy add      ---- HOOK_ADD ------->   handle_hook_add
 *                                              store the hook
 *                   <--- ACK -------------
 *
 *   policy commit   ---- POLICY_COMMIT -->   handle_policy_commit
 *                                              activate policy hooks
 *                                              rewrite matching classes
 *                   <=== METHOD_DEF ======     describe each hooked method
 *                   <--- ACK -------------
 *
 *   method call                              hook_enter
 *                   <=== METHOD_ENTRY ====     report hooked method call
 *
 *   class load                               class_file_load_hook
 *                                              rewrite the class if it matches
 *                   <=== METHOD_DEF ======     describe each hooked method
 *
 *   policy remove   ---- POLICY_REMOVE -->   handle_policy_remove
 *                                              deactivate policy hooks
 *                                              restore matching classes
 *                                              free policy hooks
 *                   <--- ACK -------------
 *
 *   Tetragon exit   ---- socket closed -->   cleanup_control_session
 *                                              restore all classes
 *                                              free all hooks
 *                                              unmap the ring
 *
 *   Tetragon start                           session_open
 *                                              connect to the control socket
 *                   <--- HELLO -----------     send JVM version
 *                   ---- ACK ------------>     session is open
 *
 *   --->  message on the control socket
 *   ===>  record in the ring
 *
 * The ring is set up only when Tetragon needs it, which is before the
 * first policy is sent to the agent.
 *
 * transform_class puts TetragonHook.enter(key) call at the entry of each
 * hooked method, hook_enter is the native implementation of that call.
 * The class is always rewritten from its original bytes, so without
 * hooks it gets back to its original form.
 */

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
#include "classfile.h"

#ifndef __maybe_unused
#define __maybe_unused __attribute__((__unused__))
#endif

#define MAX_HOOKS	1024
#define MAX_METHODS	65536
#define MAX_CLASS_NAME	4096

/*
 * Hook received from Tetragon (TG_MSG_HOOK_ADD), selects a class or all
 * classes under a package prefix and optionally their methods. The hook
 * takes effect once its policy is committed.
 */
struct hook {
	uint32_t policy_id;
	uint32_t hook_id;
	uint8_t kind;
	char *class_name;
	uint16_t nr_methods;

	struct {
		char *name;
		char *descriptor;
	} *methods;

	int committed;
	struct hook *next;
};

/*
 * Instrumented method of one hook. The key identifies the method in ring
 * records, it is unique and never reused.
 */
struct method_match {
	uint64_t key;
	uint32_t policy_id;
	uint32_t hook_id;
	char *class_name;
	char *name;
	char *descriptor;
	int defined;
	struct method_match *next;
};

/*
 * The JVM we are loaded in and our JVMTI environment, the handle for all
 * JVMTI calls. Both are set by Agent_OnAttach when it sets up the agent
 * and are not released.
 */
static JavaVM *g_vm;
static jvmtiEnv *g_jvmti;

/* Call JVMTI function fn on our environment. */
#define jvmti(fn, ...) ((*g_jvmti)->fn(g_jvmti, ##__VA_ARGS__))

/* Call JNI function fn on env, which is either JNIEnv or JavaVM. */
#define jni(env, fn, ...) ((*(env))->fn(env, ##__VA_ARGS__))

/*
 * Control session state, the socket is set up by session_open and the ring
 * by handle_ring, both are released by cleanup_control_session.
 */

/* Control socket connected to Tetragon, -1 without a session. */
static int g_sock = -1;

/* The ring memfd received from Tetragon (TG_MSG_RING), -1 without the ring. */
static int g_ring_fd = -1;

/* Mapping of the ring memfd and its length, MAP_FAILED without the ring. */
static void *g_ring_map = MAP_FAILED;
static size_t g_ring_len;

/*
 * The ring header at the start of the mapping, the data area follows it.
 * It is NULL until Tetragon sets up the ring for the session (handle_ring)
 * and ring_write drops all records then.
 */
static struct tg_ring_hdr *g_ring;

/* Protects hooks, methods and the control session (socket and ring) state. */
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

/* Serializes ring producers, taken inside g_lock. */
static pthread_mutex_t g_ring_lock = PTHREAD_MUTEX_INITIALIZER;

/* Hooks received from Tetragon in this session, both committed and not. */
static struct hook *g_hooks;

/*
 * Methods instrumented in this session, new ones are added to the head.
 * hook_enter looks up the method by its key in here.
 */
static struct method_match *g_methods;

/*
 * Key for the next method match. It is not reset with new session, so
 * the key stays unique for the whole JVM life.
 */
static uint64_t g_next_key = 1;

/* Reconnect delay in seconds, doubled after each failed attempt. */
#define RECONNECT_DELAY_MIN	1
#define RECONNECT_DELAY_MAX	5

/*
 * Tetragon's control socket path the control thread reconnects to. It is
 * updated by each Agent_OnAttach, protected by g_lock.
 */
static char g_path[sizeof(((struct sockaddr_un *)0)->sun_path)];

/*
 * Set once the agent is set up and its control thread runs, following
 * Agent_OnAttach calls only update g_path. Protected by g_lock.
 */
static int g_initialized;

/*
 * Agent_OnAttach sets g_wake and signals g_wake_cond to ask the control
 * thread to reconnect now instead of waiting for the reconnect delay.
 * Both are used with g_lock, the condition is initialized in Agent_OnAttach
 * to use the monotonic clock.
 */
static int g_wake;
static pthread_cond_t g_wake_cond;

/* Control messages and ring records are little-endian. */
static uint16_t rd16(const unsigned char *p)
{
	return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t rd32(const unsigned char *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
	       ((uint32_t)p[3] << 24);
}

/* Decode u64 in the shared little-endian protocol. */
static uint64_t rd64(const unsigned char *p)
{
	uint64_t v = 0;
	int i;

	for (i = 0; i < 8; i++)
		v |= (uint64_t)p[i] << (i * 8);
	return v;
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
	int i;

	for (i = 0; i < 8; i++)
		p[i] = (unsigned char)(v >> (i * 8));
}

/* Send one control message, struct tg_msg_hdr followed by the payload. */
static int send_packet(uint16_t type, uint32_t seq, const void *payload, size_t len)
{
	unsigned char *buf;
	ssize_t n;

	buf = calloc(1, sizeof(struct tg_msg_hdr) + len);
	if (!buf)
		return -1;
	wr16(buf, type);
	wr16(buf + 2, 0);
	wr32(buf + 4, seq);
	if (len)
		memcpy(buf + 8, payload, len);
	n = send(g_sock, buf, 8 + len, MSG_NOSIGNAL);
	free(buf);
	return n == (ssize_t)(8 + len) ? 0 : -1;
}

/*
 * Receive one control message. The file descriptor passed along with
 * SCM_RIGHTS is stored in passed_fd, -1 if there is none.
 */
static int receive_packet(unsigned char *buf, size_t cap, size_t *len, int *passed_fd)
{
	unsigned char control[CMSG_SPACE(sizeof(int))];
	struct iovec iov = {
		.iov_base = buf,
		.iov_len = cap,
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = control,
		.msg_controllen = sizeof(control),
	};
	struct cmsghdr *c;
	ssize_t n;

	n = recvmsg(g_sock, &msg, 0);
	/* The message must have at least the header and must not be truncated. */
	if (n < 8 || (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)))
		return -1;

	*len = (size_t)n;
	*passed_fd = -1;
	for (c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
		if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS &&
		    c->cmsg_len >= CMSG_LEN(sizeof(int))) {
			memcpy(passed_fd, CMSG_DATA(c), sizeof(int));
			break;
		}
	}

	return 0;
}

/* Wake up the consumer if it sleeps on the notify futex. */
static void ring_notify(void)
{
	/* Skip the syscall when the consumer does not wait. */
	if (!atomic_load_explicit((_Atomic uint32_t *)&g_ring->consumer_waiting,
				  memory_order_relaxed))
		return;
	atomic_fetch_add_explicit((_Atomic uint32_t *)&g_ring->notify, 1, memory_order_release);
	syscall(SYS_futex, &g_ring->notify, FUTEX_WAKE, 1, NULL, NULL, 0);
}

/*
 * Write one record to the ring. The record is visible to the consumer once
 * its length is stored in the record header, producer_pos is moved after
 * that. When the ring is full the record is dropped and accounted in the
 * ring header.
 */
static int ring_write(uint32_t type, const void *payload, uint32_t payload_len)
{
	uint64_t data_size, prod, cons, off, tail, need;
	struct tg_rec_hdr *hdr, *pad;
	unsigned char *area;
	uint32_t length;

	if (!g_ring)
		return -1;
	data_size = g_ring->data_size;

	/* Record length with the header, aligned to TG_REC_ALIGN. */
	length = (uint32_t)((sizeof(struct tg_rec_hdr) + payload_len + TG_REC_ALIGN - 1) &
			    ~(TG_REC_ALIGN - 1));
	if (length > data_size)
		return -1;

	pthread_mutex_lock(&g_ring_lock);
	prod = atomic_load_explicit((_Atomic uint64_t *)&g_ring->producer_pos,
				    memory_order_relaxed);
	cons = atomic_load_explicit((_Atomic uint64_t *)&g_ring->consumer_pos,
				    memory_order_acquire);

	off = prod & (data_size - 1);
	tail = data_size - off;
	need = length + (tail < length ? tail : 0);

	/* No room for the record (and the padding in front of it). */
	if (prod - cons + need > data_size) {
		if (type == TG_REC_METHOD_ENTRY)
			atomic_fetch_add(&g_ring->dropped, 1);
		else if (type == TG_REC_METHOD_DEF)
			atomic_fetch_add(&g_ring->dropped_defs, 1);
		pthread_mutex_unlock(&g_ring_lock);
		return -1;
	}

	area = (unsigned char *)g_ring_map + TG_RING_HDR_SIZE;
	/*
	 * The record does not fit before the end of the data area, fill the
	 * rest with padding record and start from the beginning.
	 */
	if (tail < length) {
		pad = (struct tg_rec_hdr *)(area + off);
		pad->len = 0;
		pad->type = TG_REC_PAD;
		memset((unsigned char *)pad + sizeof(*pad), 0, tail - sizeof(*pad));
		atomic_store_explicit((_Atomic uint32_t *)&pad->len, (uint32_t)tail,
				      memory_order_release);
		prod += tail;
		off = 0;
	}

	hdr = (struct tg_rec_hdr *)(area + off);
	/* Zero length marks the record as not committed. */
	hdr->len = 0;
	hdr->type = type;
	if (payload_len)
		memcpy((unsigned char *)hdr + sizeof(*hdr), payload, payload_len);

	/* Zero the alignment padding behind the payload. */
	memset((unsigned char *)hdr + sizeof(*hdr) + payload_len, 0,
	       length - sizeof(*hdr) - payload_len);

	/* Commit the record and publish new producer position. */
	atomic_store_explicit((_Atomic uint32_t *)&hdr->len, length, memory_order_release);
	atomic_store_explicit((_Atomic uint64_t *)&g_ring->producer_pos, prod + length,
			      memory_order_release);
	pthread_mutex_unlock(&g_ring_lock);

	ring_notify();
	return 0;
}

/*
 * Emit TG_REC_METHOD_DEF record that describes the method key:
 * u64 key, u32 policy_id, u32 hook_id, u16 class_len, u16 name_len,
 * u16 desc_len, u16 pad, followed by class, name and descriptor.
 */
static int emit_def(struct method_match *m)
{
	size_t cl = strlen(m->class_name);
	size_t nl = strlen(m->name);
	size_t dl = strlen(m->descriptor);
	unsigned char *p;
	int rc;

	if (cl > 65535 || nl > 65535 || dl > 65535)
		return -1;
	p = calloc(1, 24 + cl + nl + dl);
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

	rc = ring_write(TG_REC_METHOD_DEF, p, (uint32_t)(24 + cl + nl + dl));
	free(p);
	return rc;
}

static int eq(const char *a, const char *b)
{
	return a && b && strcmp(a, b) == 0;
}

/*
 * Hook without methods matches all methods of the class, method without
 * descriptor matches all its overloads.
 */
static int method_allowed(struct hook *h, const char *name, const char *desc)
{
	uint16_t i;

	if (h->nr_methods == 0)
		return 1;
	for (i = 0; i < h->nr_methods; i++) {
		if (eq(h->methods[i].name, name) &&
		    (!h->methods[i].descriptor[0] || eq(h->methods[i].descriptor, desc)))
			return 1;
	}

	return 0;
}

/* Class names are in JVM internal form (a/b/C), prefix hook matches a/b/. */
static int class_allowed(struct hook *h, const char *name)
{
	size_t n;

	if (h->kind == TG_HOOK_CLASS)
		return eq(h->class_name, name);
	n = strlen(h->class_name);
	return strncmp(h->class_name, name, n) == 0;
}

static struct method_match *find_method(const char *class_name, const char *name, const char *desc,
					uint32_t policy_id, uint32_t hook_id)
{
	struct method_match *m;

	for (m = g_methods; m; m = m->next) {
		if (m->policy_id == policy_id && m->hook_id == hook_id &&
		    eq(m->class_name, class_name) && eq(m->name, name) && eq(m->descriptor, desc))
			return m;
	}

	return NULL;
}

/*
 * Get the match for the method and hook, new one is added with fresh key
 * if it does not exist yet.
 */
static struct method_match *add_method(const char *class_name, const char *name, const char *desc,
				       uint32_t policy_id, uint32_t hook_id)
{
	struct method_match *m;

	m = find_method(class_name, name, desc, policy_id, hook_id);
	if (m)
		return m;

	m = calloc(1, sizeof(*m));
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

/*
 * Read u16 length prefixed string at offset off, returns allocated zero
 * terminated copy and moves off behind the string.
 */
static char *get_string(const unsigned char *p, size_t len, size_t *off)
{
	uint16_t n;
	char *s;

	if (*off + 2 > len)
		return NULL;

	n = rd16(p + *off);
	*off += 2;
	if (n > len - *off)
		return NULL;

	s = calloc(1, (size_t)n + 1);
	if (!s)
		return NULL;
	memcpy(s, p + *off, n);
	*off += n;
	return s;
}

static void free_hook(struct hook *h)
{
	uint16_t i;

	if (!h)
		return;
	free(h->class_name);
	for (i = 0; i < h->nr_methods; i++) {
		free(h->methods[i].name);
		free(h->methods[i].descriptor);
	}

	free(h->methods);
	free(h);
}

/*
 * Parse TG_MSG_HOOK_ADD payload: u32 policy_id, u32 hook_id, u8 kind,
 * u8 pad, u16 nr_methods, class name and name plus descriptor string for
 * each method.
 */
static struct hook *parse_hook(const unsigned char *p, size_t len)
{
	size_t off = 12;
	struct hook *h;
	uint16_t i;

	if (len < 14)
		return NULL;

	h = calloc(1, sizeof(*h));
	if (!h)
		return NULL;

	h->policy_id = rd32(p);
	h->hook_id = rd32(p + 4);
	h->kind = p[8];
	h->nr_methods = rd16(p + 10);
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

	for (i = 0; i < h->nr_methods; i++) {
		h->methods[i].name = get_string(p, len, &off);
		h->methods[i].descriptor = get_string(p, len, &off);
		if (!h->methods[i].name || !h->methods[i].descriptor)
			goto fail;
	}

	/* No trailing data is allowed. */
	if (off != len)
		goto fail;
	return h;

fail:
	free_hook(h);
	return NULL;
}

/*
 * classfile_instrument callback, provides keys for the method of the class
 * in ctx, one for each committed hook that matches it.
 *
 * Called with g_lock held.
 */
static int class_keys(void *ctx, const char *name, const char *desc, uint64_t **keys)
{
	const char *class_name = ctx;
	uint64_t *k = NULL, *tmp;
	struct method_match *m;
	struct hook *h;
	int count = 0;

	for (h = g_hooks; h; h = h->next) {
		if (!h->committed || !class_allowed(h, class_name) ||
		    !method_allowed(h, name, desc))
			continue;

		m = add_method(class_name, name, desc, h->policy_id, h->hook_id);
		tmp = m ? realloc(k, (count + 1) * sizeof(*k)) : NULL;
		if (!tmp) {
			free(k);
			return -1;
		}

		k = tmp;
		k[count++] = m->key;
	}

	*keys = k;
	return count;
}

/*
 * Rewrite the class so all its methods matching committed hooks call
 * TetragonHook.enter(key) at entry and emit definition of each new method
 * key. The class file is rewritten by classfile_instrument.
 *
 * Returns 1 with the new class in out, 0 if the class stays unchanged.
 *
 * Called with g_lock held.
 */
static int transform_class(const char *class_name, const unsigned char *data, size_t len,
			   unsigned char **out, size_t *out_len)
{
	struct method_match *old_head, *m;

	/*
	 * New method matches are added to the head of g_methods, so they can
	 * be dropped if the class stays unchanged.
	 */
	old_head = g_methods;

	if (!classfile_instrument(data, len, class_keys, (void *)class_name, out, out_len)) {
		while (g_methods != old_head) {
			m = g_methods;
			g_methods = m->next;
			free(m->class_name);
			free(m->name);
			free(m->descriptor);
			free(m);
		}
		return 0;
	}

	/*
	 * Tell Tetragon about new method keys. If the record gets dropped,
	 * hook_enter emits it again.
	 */
	for (m = g_methods; m != old_head; m = m->next)
		m->defined = emit_def(m) == 0;

	return 1;
}

/*
 * Native implementation of TetragonHook.enter(long key), called at the
 * entry of each instrumented method. Emits TG_REC_METHOD_ENTRY record:
 * u64 key, u64 ktime, u32 tid, u32 pad.
 */
static void JNICALL hook_enter(JNIEnv *jni __maybe_unused, jclass klass __maybe_unused, jlong key)
{
	struct method_match *m;
	struct timespec ts;
	uint64_t ktime;
	uint32_t tid;

	/* CLOCK_MONOTONIC is the clock of bpf_ktime_get_ns used for BPF events. */
	clock_gettime(CLOCK_MONOTONIC, &ts);
	ktime = (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
	tid = (uint32_t)syscall(SYS_gettid);

	pthread_mutex_lock(&g_lock);
	for (m = g_methods; m; m = m->next) {
		if (m->key != (uint64_t)key)
			continue;

		/* Emit the definition again if it was dropped before. */
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

/* JDK classes and our hook class are never instrumented. */
static int excluded_class(const char *name)
{
	return !name || strncmp(name, "java/", 5) == 0 || strncmp(name, "jdk/", 4) == 0 ||
	       strncmp(name, "sun/", 4) == 0 || strncmp(name, "io/tetragon/", 12) == 0;
}

/*
 * Called by the JVM for each class being loaded or retransformed with the
 * class file bytes. The class stays unchanged unless new_bytes is set.
 */
static void JNICALL class_file_load_hook(jvmtiEnv *jvmti, JNIEnv *jni __maybe_unused,
					 jclass redefining __maybe_unused,
					 jobject loader __maybe_unused, const char *name,
					 jobject domain __maybe_unused, jint len,
					 const unsigned char *bytes, jint *new_len,
					 unsigned char **new_bytes)
{
	unsigned char *transformed = NULL;
	size_t transformed_len = 0;
	int rc;

	if (len <= 0 || excluded_class(name))
		return;

	pthread_mutex_lock(&g_lock);
	rc = transform_class(name, bytes, (size_t)len, &transformed, &transformed_len);

	/* The JVM expects (and frees) the new class in JVMTI allocated memory. */
	if (rc == 1 && transformed_len <= INT32_MAX &&
	    (*jvmti)->Allocate(jvmti, (jlong)transformed_len, new_bytes) == JVMTI_ERROR_NONE) {
		memcpy(*new_bytes, transformed, transformed_len);
		*new_len = (jint)transformed_len;
	}
	pthread_mutex_unlock(&g_lock);
	free(transformed);
}

/*
 * Retransform already loaded classes that match hooks of the policy (and
 * all committed hooks with include_committed), so the JVM calls
 * class_file_load_hook for them and they get rewritten based on the
 * current hooks.
 *
 * Called without g_lock, class_file_load_hook takes it.
 */
static void retransform_policy_classes(uint32_t policy_id, int include_committed)
{
	jclass *classes = NULL;
	jint count = 0, i;

	if (jvmti(GetLoadedClasses, &count, &classes) != JVMTI_ERROR_NONE)
		return;
	for (i = 0; i < count; i++) {
		char *sig = NULL, *generic = NULL, *name;
		jboolean modifiable = JNI_FALSE;
		jvmtiError e = JVMTI_ERROR_NONE;
		int selected = 0;
		struct hook *h;
		size_t n;

		jvmti(GetClassSignature, classes[i], &sig, &generic);

		/* Class signature is "La/b/C;", get the a/b/C name. */
		if (sig && sig[0] == 'L') {
			n = strlen(sig);
			name = calloc(1, n - 1);
			if (name) {
				memcpy(name, sig + 1, n - 2);
				pthread_mutex_lock(&g_lock);
				for (h = g_hooks; h; h = h->next) {
					if ((h->policy_id == policy_id ||
					     (include_committed && h->committed)) &&
					    class_allowed(h, name)) {
						selected = 1;
						break;
					}
				}
				pthread_mutex_unlock(&g_lock);
				free(name);
			}
		}

		/* Skip classes the JVM is not able to modify. */
		if (selected)
			e = jvmti(IsModifiableClass, classes[i], &modifiable);
		if (sig)
			jvmti(Deallocate, (unsigned char *)sig);
		if (generic)
			jvmti(Deallocate, (unsigned char *)generic);
		if (!selected || e != JVMTI_ERROR_NONE || !modifiable)
			continue;

		/* One class at a time, so a failure does not affect other classes. */
		e = jvmti(RetransformClasses, 1, &classes[i]);
		if (e != JVMTI_ERROR_NONE)
			fprintf(stderr, "tetragon-jvmti: class retransformation failed (%d)\n", e);
	}

	jvmti(Deallocate, (unsigned char *)classes);
}

/*
 * Close the control session: remove the instrumentation from all classes,
 * free hooks and methods and release the ring and the control socket.
 */
static void cleanup_control_session(void)
{
	size_t count = 0, capacity = 0, ring_len, next, i;
	int ring_fd, fd, seen;
	struct method_match *m;
	uint32_t *ids = NULL, *p;
	struct hook *h;
	void *ring_map;

	pthread_mutex_lock(&g_lock);
	/* Uncommit all hooks and collect ids of their policies. */
	for (h = g_hooks; h; h = h->next) {
		h->committed = 0;
		seen = 0;
		for (i = 0; i < count; i++) {
			if (ids[i] == h->policy_id) {
				seen = 1;
				break;
			}
		}

		if (seen)
			continue;
		if (count == capacity) {
			next = capacity ? capacity * 2 : 8;
			p = realloc(ids, next * sizeof(*p));
			if (!p)
				break;
			ids = p;
			capacity = next;
		}

		ids[count++] = h->policy_id;
	}
	pthread_mutex_unlock(&g_lock);

	/* No hook is committed now, so the classes are rewritten without the calls. */
	for (i = 0; i < count; i++)
		retransform_policy_classes(ids[i], 0);
	free(ids);

	pthread_mutex_lock(&g_lock);
	while (g_hooks) {
		h = g_hooks;
		g_hooks = h->next;
		free_hook(h);
	}

	while (g_methods) {
		m = g_methods;
		g_methods = m->next;
		free(m->class_name);
		free(m->name);
		free(m->descriptor);
		free(m);
	}

	/* Detach the session state under the lock and release it outside. */
	g_ring = NULL;
	ring_map = g_ring_map;
	ring_len = g_ring_len;
	ring_fd = g_ring_fd;
	g_ring_map = MAP_FAILED;
	g_ring_len = 0;
	g_ring_fd = -1;
	fd = g_sock;
	g_sock = -1;
	pthread_mutex_unlock(&g_lock);

	if (fd >= 0)
		close(fd);
	if (ring_map != MAP_FAILED)
		munmap(ring_map, ring_len);
	if (ring_fd >= 0)
		close(ring_fd);
}

/*
 * Define the TetragonHook class (if not defined already) in the bootstrap
 * class loader, so it is visible to all classes, and bind its native
 * enter method to hook_enter.
 */
static int define_hook_class(JNIEnv *env)
{
	JNINativeMethod method = {
		.name = "enter",
		.signature = "(J)V",
		.fnPtr = (void *)hook_enter,
	};
	jclass klass;

	/*
	 * The class is already there if previous attach got this far and
	 * failed later. Failed lookup leaves NoClassDefFoundError pending,
	 * it must be cleared before any other JNI call.
	 */
	klass = jni(env, FindClass, "io/tetragon/TetragonHook");
	if (!klass) {
		jni(env, ExceptionClear);

		/*
		 * NULL loader is the bootstrap class loader. The class bytes
		 * are compiled jvmti/TetragonHook.java, see tetragonhook.h.
		 */
		klass = jni(env, DefineClass, "io/tetragon/TetragonHook", NULL,
			    (const jbyte *)tetragon_hook_class, (jsize)sizeof(tetragon_hook_class));
	}

	if (!klass)
		return -1;

	/*
	 * Bind the native method explicitly, the JVM would not find it by
	 * the Java_io_tetragon_TetragonHook_enter symbol lookup, because the
	 * agent library is not loaded through System.loadLibrary.
	 */
	return jni(env, RegisterNatives, klass, &method, 1) == JNI_OK ? 0 : -1;
}

/*
 * Send TG_MSG_ACK for the command with seq: u32 seq, i32 status,
 * u32 classes, u16 error length and the error string.
 */
static int ack(uint32_t seq, int32_t status, uint32_t classes, const char *error)
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

/*
 * TG_MSG_HOOK_ADD: store the hook. It is not active until its policy is
 * committed.
 */
static int handle_hook_add(const unsigned char *p, size_t n)
{
	struct hook *h, *it;
	int duplicate = 0;

	h = parse_hook(p, n);
	if (!h)
		return -1;

	pthread_mutex_lock(&g_lock);
	for (it = g_hooks; it; it = it->next) {
		if (it->policy_id == h->policy_id && it->hook_id == h->hook_id) {
			duplicate = 1;
			break;
		}
	}

	/* The list takes over the hook, duplicate hook is dropped. */
	if (!duplicate) {
		h->next = g_hooks;
		g_hooks = h;
		h = NULL;
	}
	pthread_mutex_unlock(&g_lock);
	free_hook(h);
	return 0;
}

/*
 * TG_MSG_POLICY_COMMIT: activate hooks of the policy and instrument
 * matching classes.
 */
static int handle_policy_commit(const unsigned char *p, size_t n)
{
	struct hook *h;
	uint32_t id;

	if (n != 4)
		return -1;

	id = rd32(p);
	pthread_mutex_lock(&g_lock);
	/* The hooked methods report through the ring, it must be set up first. */
	if (!g_ring) {
		pthread_mutex_unlock(&g_lock);
		return -1;
	}

	for (h = g_hooks; h; h = h->next) {
		if (h->policy_id == id)
			h->committed = 1;
	}
	pthread_mutex_unlock(&g_lock);

	retransform_policy_classes(id, 0);
	return 0;
}

/*
 * TG_MSG_POLICY_REMOVE: remove hooks of the policy together with the
 * instrumentation.
 */
static int handle_policy_remove(const unsigned char *p, size_t n)
{
	struct method_match *removed = NULL, **mp, *old;
	struct hook *h, **hp;
	uint32_t id;

	if (n != 4)
		return -1;

	id = rd32(p);
	pthread_mutex_lock(&g_lock);
	for (h = g_hooks; h; h = h->next) {
		if (h->policy_id == id)
			h->committed = 0;
	}
	pthread_mutex_unlock(&g_lock);

	/*
	 * The hooks are still in the list, but not committed, so the
	 * classes are rewritten without them.
	 */
	retransform_policy_classes(id, 1);

	pthread_mutex_lock(&g_lock);
	/* Free hooks and method matches of the policy. */
	hp = &g_hooks;
	while (*hp) {
		if ((*hp)->policy_id == id) {
			h = *hp;
			*hp = h->next;
			free_hook(h);
		} else {
			hp = &(*hp)->next;
		}
	}

	mp = &g_methods;
	while (*mp) {
		if ((*mp)->policy_id == id) {
			old = *mp;
			*mp = old->next;
			old->next = removed;
			removed = old;
		} else {
			mp = &(*mp)->next;
		}
	}

	while (removed) {
		old = removed;
		removed = removed->next;
		free(old->class_name);
		free(old->name);
		free(old->descriptor);
		free(old);
	}
	pthread_mutex_unlock(&g_lock);
	return 0;
}

/*
 * TG_MSG_RING: map the ring that Tetragon hands over, the payload is u64
 * ring length and the ring memfd comes with SCM_RIGHTS. Tetragon sends it
 * before the first policy, there is one ring for the session.
 *
 * The fd is taken over on success, the caller closes it otherwise.
 */
static int handle_ring(const unsigned char *p, size_t n, int fd)
{
	struct tg_ring_hdr *ring;
	size_t ring_len;
	void *ring_map;
	int has_ring;

	if (n != 8 || fd < 0)
		return -1;

	pthread_mutex_lock(&g_lock);
	has_ring = g_ring != NULL;
	pthread_mutex_unlock(&g_lock);

	if (has_ring)
		return -1;

	ring_len = (size_t)rd64(p);
	if (ring_len < TG_RING_HDR_SIZE + 1024)
		return -1;

	ring_map = mmap(NULL, ring_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (ring_map == MAP_FAILED)
		return -1;

	ring = (struct tg_ring_hdr *)ring_map;
	/* Check the ring header prepared by Tetragon. */
	if (ring->magic != TG_RING_MAGIC || ring->version != TG_RING_VERSION ||
	    ring->data_size != ring_len - TG_RING_HDR_SIZE) {
		munmap(ring_map, ring_len);
		return -1;
	}

	pthread_mutex_lock(&g_lock);
	/* Publish the ring, hook_enter can write records from now on. */
	g_ring_fd = fd;
	g_ring_map = ring_map;
	g_ring_len = ring_len;
	g_ring = ring;
	pthread_mutex_unlock(&g_lock);
	return 0;
}

/*
 * Handle one command from Tetragon and acknowledge it, unknown or malformed
 * command is acknowledged with an error. The fd is the file descriptor that
 * came with the command, -1 if there is none.
 */
static int handle_command(unsigned char *buf, size_t len, int fd)
{
	const unsigned char *p = buf + 8;
	uint32_t seq = rd32(buf + 4);
	uint16_t type = rd16(buf);
	size_t n = len - 8;
	int status;

	switch (type) {
	case TG_MSG_RING:
		status = handle_ring(p, n, fd);
		/* The ring keeps the fd. */
		if (!status)
			fd = -1;
		break;
	case TG_MSG_HOOK_ADD:
		status = handle_hook_add(p, n);
		break;
	case TG_MSG_POLICY_COMMIT:
		status = handle_policy_commit(p, n);
		break;
	case TG_MSG_POLICY_REMOVE:
		status = handle_policy_remove(p, n);
		break;
	default:
		status = -1;
		break;
	}

	/* Other commands do not carry file descriptors. */
	if (fd >= 0)
		close(fd);

	return ack(seq, status, 0, status ? "invalid or unsupported command" : "");
}

/* Connect to the Tetragon control socket, returns the socket or -1. */
static int connect_control(const char *path)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	int fd;

	if (!path || strlen(path) >= sizeof(((struct sockaddr_un *)0)->sun_path))
		return -1;
	fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
		close(fd);
		return -1;
	}

	return fd;
}

/*
 * Open the control session with Tetragon: connect to its socket, say HELLO
 * and wait for Tetragon to accept it. Nothing is left behind on failure.
 * The failure is reported only for verbose, the reconnect attempts fail
 * silently while Tetragon is away.
 *
 * The session has no ring, Tetragon sets it up with TG_MSG_RING command
 * when it is needed.
 */
static int session_open(const char *path, int verbose)
{
	unsigned char packet[8 + 4 + 2 + 255] = {0};
	unsigned char buf[TG_MSG_MAX_SIZE];
	size_t version_len, n = 0;
	char *vm_version = NULL;
	int control_fd;
	int passed = -1;

	control_fd = connect_control(path);
	if (control_fd < 0) {
		if (verbose)
			fprintf(stderr, "tetragon-jvmti: connect failed for %s: %s\n", path,
				strerror(errno));
		return -1;
	}

	pthread_mutex_lock(&g_lock);
	g_sock = control_fd;
	pthread_mutex_unlock(&g_lock);

	jvmti(GetSystemProperty, "java.vm.version", &vm_version);
	version_len = vm_version ? strlen(vm_version) : 0;
	if (version_len > 255)
		version_len = 255;

	/* HELLO: header, u32 protocol version, u16 length and the JVM version. */
	wr16(packet, TG_MSG_HELLO);
	wr32(packet + 4, 0);
	wr32(packet + 8, TG_PROTO_VERSION);
	wr16(packet + 12, (uint16_t)version_len);
	if (version_len)
		memcpy(packet + 14, vm_version, version_len);
	if (vm_version)
		jvmti(Deallocate, (unsigned char *)vm_version);

	if (send(g_sock, packet, 14 + version_len, MSG_NOSIGNAL) != (ssize_t)(14 + version_len)) {
		if (verbose)
			fprintf(stderr, "tetragon-jvmti: HELLO send failed\n");
		goto fail;
	}

	/*
	 * Tetragon accepts the session with ACK: header, u32 seq, i32 status,
	 * u32 classes and the error string. It closes the connection without
	 * a reply if it does not know this process.
	 */
	if (receive_packet(buf, sizeof(buf), &n, &passed) != 0 || rd16(buf) != TG_MSG_ACK ||
	    n < 8 + 14 || rd32(buf + 12) != 0) {
		if (verbose)
			fprintf(stderr, "tetragon-jvmti: HELLO was not accepted n=%zu type=%u\n", n,
				n >= 2 ? rd16(buf) : 0);
		if (passed >= 0)
			close(passed);
		goto fail;
	}

	/* The reply does not carry file descriptor. */
	if (passed >= 0)
		close(passed);
	return 0;

fail:
	cleanup_control_session();
	return -1;
}

/*
 * Wait before the next reconnect attempt, Agent_OnAttach cuts the wait
 * short when Tetragon attaches again.
 */
static void reconnect_wait(unsigned int delay)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	ts.tv_sec += delay;

	pthread_mutex_lock(&g_lock);
	/* The timeout (or an error) ends the wait as well. */
	while (!g_wake) {
		if (pthread_cond_timedwait(&g_wake_cond, &g_lock, &ts) != 0)
			break;
	}

	g_wake = 0;
	pthread_mutex_unlock(&g_lock);
}

/*
 * The control thread serves the session opened by Agent_OnAttach. When the
 * session ends (Tetragon exited or restarted), it removes the hooks and keeps
 * trying to connect back, so Tetragon does not need to attach again.
 */
static void *control_thread(void *unused __maybe_unused)
{
	static unsigned char buf[TG_MSG_MAX_SIZE];
	JavaVMAttachArgs args = {
		.version = JNI_VERSION_1_6,
		.name = "tetragon-jvmti-control",
		.group = NULL,
	};
	unsigned int delay = RECONNECT_DELAY_MIN;
	int connected = 1;
	JNIEnv *env = NULL;

	/*
	 * The thread needs to be attached to the JVM to use JVMTI, daemon
	 * thread does not block the JVM exit.
	 */
	if (jni(g_vm, AttachCurrentThreadAsDaemon, (void **)&env, &args) != JNI_OK) {
		cleanup_control_session();
		pthread_mutex_lock(&g_lock);
		g_initialized = 0;
		pthread_mutex_unlock(&g_lock);
		return NULL;
	}

	for (;;) {
		if (!connected) {
			char path[sizeof(g_path)];

			pthread_mutex_lock(&g_lock);
			memcpy(path, g_path, sizeof(path));
			pthread_mutex_unlock(&g_lock);

			connected = session_open(path, 0) == 0;
		}

		if (connected) {
			for (;;) {
				size_t n = 0;
				int fd = -1;

				/* Serve commands until the session breaks. */
				if (receive_packet(buf, sizeof(buf), &n, &fd))
					break;

				if (handle_command(buf, n, fd))
					break;
			}

			cleanup_control_session();
			connected = 0;
			delay = RECONNECT_DELAY_MIN;
		}

		/* Back off up to RECONNECT_DELAY_MAX between the attempts. */
		reconnect_wait(delay);
		delay *= 2;
		if (delay > RECONNECT_DELAY_MAX)
			delay = RECONNECT_DELAY_MAX;
	}

	return NULL;
}

/*
 * Called by the JVM when Tetragon loads the agent, options carry the path
 * of the control socket. The first attach sets up the agent, opens the
 * control session and starts the control thread. Following attaches only
 * pass new socket path to the control thread.
 *
 * The first attach goes through following steps:
 *   - get the JVMTI environment
 *   - open the control session (HELLO and its ACK)
 *   - add JVMTI capabilities needed to rewrite classes
 *   - define the TetragonHook class
 *   - register and enable the ClassFileLoadHook event
 *   - start the control thread
 *
 * The function runs in the JVM's attach listener thread, which is a Java
 * thread, so both JVMTI and JNI are available. The return value is passed
 * back to Tetragon as the result of the load command. The library stays
 * loaded even when we fail, so the next attach comes here again with
 * g_initialized not set and starts from scratch.
 */
JNIEXPORT jint JNICALL Agent_OnAttach(JavaVM *vm, char *options, void *reserved __maybe_unused)
{
	jvmtiEventCallbacks callbacks = {0};
	jvmtiCapabilities caps = {0};
	pthread_condattr_t attr;
	JNIEnv *env = NULL;
	pthread_t thread;
	jvmtiError jerr;
	int perr;

	if (!options || !options[0]) {
		fprintf(stderr, "tetragon-jvmti: no socket option\n");
		return JNI_ERR;
	}
	if (strlen(options) >= sizeof(g_path)) {
		fprintf(stderr, "tetragon-jvmti: socket path too long\n");
		return JNI_ERR;
	}

	pthread_mutex_lock(&g_lock);
	if (g_initialized) {
		/*
		 * The agent is already in this JVM, take the socket path
		 * and let the control thread connect right away.
		 */
		strcpy(g_path, options);
		g_wake = 1;
		pthread_cond_signal(&g_wake_cond);
		pthread_mutex_unlock(&g_lock);
		return JNI_OK;
	}
	pthread_mutex_unlock(&g_lock);

	/* The control thread needs the JavaVM to attach itself to the JVM. */
	g_vm = vm;

	/*
	 * Get the JVMTI environment, the handle for all JVMTI calls. Each
	 * GetEnv call with JVMTI version creates new environment with its
	 * own capabilities, callbacks and enabled events, so nothing we set
	 * up below affects other agents in the JVM.
	 *
	 * The version is the lowest JVMTI version we ask the JVM to support,
	 * RetransformClasses is there since 1.1.
	 */
	if (jni(vm, GetEnv, (void **)&g_jvmti, JVMTI_VERSION_1_2) != JNI_OK || !g_jvmti) {
		fprintf(stderr, "tetragon-jvmti: GetEnv failed\n");
		return JNI_ERR;
	}

	/*
	 * Fail the attach early if Tetragon is not reachable. This is done
	 * before the JVM gets changed in any way, but after we have g_jvmti,
	 * session_open uses it to read the JVM version for HELLO.
	 */
	if (session_open(options, 1) != 0)
		return JNI_ERR;

	/*
	 * Capabilities are off by default and must be added before the
	 * functions and events they guard are used:
	 *
	 *   can_retransform_classes
	 *     Allows RetransformClasses, which we use to instrument classes
	 *     that are already loaded. It also makes ClassFileLoadHook of
	 *     this environment to be called for retransformed classes, not
	 *     just for the newly loaded ones.
	 *
	 *   can_generate_all_class_hook_events
	 *     ClassFileLoadHook is generated for every class the JVM loads.
	 *
	 * We are attached to the running JVM (live phase), where only some
	 * capabilities can be added, HotSpot allows both of these.
	 */
	caps.can_generate_all_class_hook_events = 1;
	caps.can_retransform_classes = 1;
	jerr = jvmti(AddCapabilities, &caps);
	if (jerr != JVMTI_ERROR_NONE) {
		fprintf(stderr, "tetragon-jvmti: AddCapabilities failed %d\n", jerr);
		goto fail;
	}

	/*
	 * TetragonHook must exist before any class gets instrumented, so
	 * define it before the ClassFileLoadHook is enabled. This time GetEnv
	 * is called with JNI version and returns the JNIEnv of the current
	 * thread, which is needed for JNI calls in define_hook_class.
	 */
	if (jni(vm, GetEnv, (void **)&env, JNI_VERSION_1_6) != JNI_OK ||
	    define_hook_class(env) != 0) {
		fprintf(stderr, "tetragon-jvmti: failed to define TetragonHook bootstrap class\n");
		goto fail;
	}

	/*
	 * Register the event callbacks. The call sets the whole callback
	 * table of the environment, events with NULL callback are not
	 * delivered. The size tells the JVM which version of the table we
	 * were compiled with.
	 */
	callbacks.ClassFileLoadHook = class_file_load_hook;
	jerr = jvmti(SetEventCallbacks, &callbacks, sizeof(callbacks));
	if (jerr != JVMTI_ERROR_NONE) {
		fprintf(stderr, "tetragon-jvmti: SetEventCallbacks failed %d\n", jerr);
		goto fail;
	}

	/*
	 * Registered callback is not called until its event is enabled, NULL
	 * thread enables it for all threads. From now on class_file_load_hook
	 * can run in any thread that loads a class, even before we return.
	 * No hook is committed yet, so it leaves all classes unchanged.
	 */
	jerr = jvmti(SetEventNotificationMode, JVMTI_ENABLE, JVMTI_EVENT_CLASS_FILE_LOAD_HOOK, NULL);
	if (jerr != JVMTI_ERROR_NONE) {
		fprintf(stderr, "tetragon-jvmti: enable class load hook failed %d\n", jerr);
		goto fail;
	}

	/* reconnect_wait uses monotonic clock for the timeout. */
	pthread_condattr_init(&attr);
	pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
	pthread_cond_init(&g_wake_cond, &attr);
	pthread_condattr_destroy(&attr);

	pthread_mutex_lock(&g_lock);
	strcpy(g_path, options);
	g_wake = 0;
	g_initialized = 1;
	pthread_mutex_unlock(&g_lock);

	perr = pthread_create(&thread, NULL, control_thread, NULL);
	if (perr != 0) {
		fprintf(stderr, "tetragon-jvmti: control thread create failed %d\n", perr);
		pthread_mutex_lock(&g_lock);
		g_initialized = 0;
		pthread_mutex_unlock(&g_lock);
		goto fail;
	}

	pthread_detach(thread);
	return JNI_OK;

fail:
	/*
	 * Close the session opened above. The JVMTI setup is not reverted,
	 * the capabilities, the TetragonHook class and possibly enabled
	 * ClassFileLoadHook stay, but they do nothing without hooks.
	 */
	cleanup_control_session();
	return JNI_ERR;
}
