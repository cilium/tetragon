// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

#ifndef __TETRAGON_DEBUG_H__
#define __TETRAGON_DEBUG_H__

#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "common.h"

#ifdef TETRAGON_BPF_DEBUG
// Enable perf debug for 5.13+ kernels by default, or when explicitly enabled
#if defined(__V513_BPF_PROG) || defined(TETRAGON_PERF_DEBUG)

// Maximum size of the formatted message
#define BPF_DEBUG_DATA_MAX_LEN 4096

// Debug event structure that will be sent over perf buffer
struct debug_event {
	__u64 timestamp;
	__u32 pid;
	__u32 cpu;
	char data[BPF_DEBUG_DATA_MAX_LEN]; // null-terminated formatted string
};

// Per-CPU heap allocation map for debug event structures
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1); // Single entry per CPU
	__type(key, __u32);
	__type(value, struct debug_event);
} debug_heap SEC(".maps");

// Map definition for perf event buffer
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(key, __u32);
	__type(value, struct debug_event);
} debug_events SEC(".maps");

// Helper function to get debug buffer from per-CPU heap
FUNC_INLINE struct debug_event *get_debug_buffer(void)
{
	__u32 key = 0;

	return map_lookup_elem(&debug_heap, &key);
}

// Helper function to send debug event via perf buffer
FUNC_INLINE void send_debug_event(void *ctx, struct debug_event *event)
{
	perf_event_output(ctx, &debug_events, BPF_F_CURRENT_CPU,
			  event, sizeof(*event));
}

/* The argument reuse is fine here since the two uses are necessarily mutually
 * exclusive due to the if statement.
 * checkpatch-ignore: MACRO_ARGUMENT_REUSE
 */
#define DEBUG(ctx, fmt, ...)                                                               \
	do {                                                                               \
		struct debug_event *event = get_debug_buffer();                            \
		if (event) {                                                               \
			event->timestamp = ktime_get_ns();                                 \
			event->pid = get_current_pid_tgid() >> 32;                         \
			event->cpu = get_smp_processor_id();                               \
			/* Use snprintf to format directly into the buffer */              \
			/* Create args array - snprintf expects void* for variadic args */ \
			__u64 _args[] = { 0, ##__VA_ARGS__ };                              \
			int _arg_count = (sizeof(_args) / sizeof(__u64)) - 1;              \
			if (_arg_count > 0) {                                              \
				snprintf(event->data, BPF_DEBUG_DATA_MAX_LEN, fmt,         \
					 (void *)&_args[1], _arg_count * sizeof(__u64));   \
			} else {                                                           \
				snprintf(event->data, BPF_DEBUG_DATA_MAX_LEN, fmt,         \
					 (void *)0, 0);                                    \
			}                                                                  \
			send_debug_event(ctx, event);                                      \
		}                                                                          \
	} while (0)

#else // !(__V513_BPF_PROG || TETRAGON_PERF_DEBUG)

// Fallback to traditional bpf_printk when perf debug is disabled or on older kernels
#define DEBUG(__ctx, __fmt, ...) bpf_printk(__fmt, ##__VA_ARGS__)

#endif // __V513_BPF_PROG || TETRAGON_PERF_DEBUG
#else // !TETRAGON_BPF_DEBUG
#define DEBUG(__ctx, __fmt, ...)
#endif // !TETRAGON_BPF_DEBUG

#endif // __TETRAGON_DEBUG_H__
