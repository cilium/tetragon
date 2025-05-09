#include "bpf_helpers.h"
#include "ebpf_ntos_hooks.h"

#define IMAGE_PATH_SIZE (1024)

// 64k bytes is the max byte count that fits in a UNICODE_STRING (because Length is a USHORT).  Exactly 64k seems
// to be a little too high for eBPF, so we subtract a few bytes and the likelihood this actually truncates anything
// important is pretty low.
#define COMMAND_SCRATCH_SIZE ((64 * 1024) - 16)

#define MSG_OP_EXECVE 5
#define MSG_OP_EXIT   7

struct msg_common {
	uint8_t op;
	uint8_t flags; // internal flags not exported
	uint8_t pad[2];
	uint32_t size;
	uint64_t ktime;
};

// Declare a per-CPU array to be used as scratch space.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, uint64_t); // key is pid_tgid
	__uint(value_size, COMMAND_SCRATCH_SIZE);
	__uint(max_entries, 1);
} temp SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, uint64_t); // key is pid_tgid
	__uint(value_size, COMMAND_SCRATCH_SIZE);
	__uint(max_entries, 1024);
} scratch_space SEC(".maps");

// The non variable fields from the process_md_t struct.
// Note: this must be kept in sync with the C# version in process_monitor.Library's ProcessMonitorBPFLoader.cs
struct process_create_info_t {
	struct msg_common common;
	uint32_t process_id;
	uint32_t parent_process_id;
	uint32_t creating_process_id;
	uint32_t creating_thread_id;
	uint64_t creation_time; ///< Process creation time.
};

struct process_exit_info_t {
	struct msg_common common;
	uint32_t process_id;
	uint64_t exit_time; ///< Process exit time.
	uint32_t process_exit_code;
	uint8_t operation;
};

// LRU hash for storing the image path of a process.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, uint32_t); // key is the process id.
	__type(value, char[IMAGE_PATH_SIZE]);
	__uint(max_entries, 1024);
} process_map SEC(".maps");

// LRU hash for storing the command line of a process.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, uint32_t); // key is the process id.
	__type(value, char[COMMAND_SCRATCH_SIZE]);
	__uint(max_entries, 1024);
} command_map SEC(".maps");

// Ring-buffer for process_info_t.
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} process_ringbuf SEC(".maps");

// The following line is optional, but is used to verify
// that the ProcesMonitor prototype is correct or the compiler
// would complain when the function is actually defined below.
process_hook_t ProcessMonitor;

inline __attribute__((always_inline)) void *
get_scratch_space()
{
	uint64_t current_pid_tgid_key = bpf_get_current_pid_tgid();
	void *scratch = bpf_map_lookup_elem(&temp, &current_pid_tgid_key);

	if (!scratch) {
		uint32_t temp_key = 0;
		// Allocate scratch space for this CPU.
		scratch = bpf_map_lookup_elem(&temp, &temp_key);

		if (!scratch)
			return NULL;

		// Insert into the LRU map.
		bpf_map_update_elem(&scratch_space, &current_pid_tgid_key, scratch, BPF_ANY);

		// Get the pointer to the scratch space.
		scratch = bpf_map_lookup_elem(&scratch_space, &current_pid_tgid_key);
		if (!scratch)
			return NULL;

		// Initialize the scratch space.
		memset(scratch, 0, COMMAND_SCRATCH_SIZE);
	}
	return scratch;
}

SEC("process")
int ProcessMonitor(process_md_t *ctx)
{
	if (ctx->operation == PROCESS_OPERATION_CREATE) {
		struct process_create_info_t process_create_info;

		memset(&process_create_info, 0, sizeof(process_create_info));
		process_create_info.common.op = MSG_OP_EXECVE;
		process_create_info.process_id = ctx->process_id;
		process_create_info.parent_process_id = ctx->parent_process_id;
		process_create_info.creating_process_id = ctx->creating_process_id;
		process_create_info.creating_thread_id = ctx->creating_thread_id;
		process_create_info.common.ktime = ctx->creation_time;
		process_create_info.creation_time = ctx->creation_time;

		void *buffer = get_scratch_space();

		if (!buffer)
			return 0;
		int command_length = ctx->command_end - ctx->command_start;
		if (command_length > COMMAND_SCRATCH_SIZE)
			command_length = COMMAND_SCRATCH_SIZE;

		// Use COMMAND_SCRATCH_SIZE -1 to ensure the last byte stays a 0 for null termination
		memcpy_s(buffer, COMMAND_SCRATCH_SIZE - 1, ctx->command_start, command_length);

		bpf_map_update_elem(&command_map, &process_create_info.process_id, buffer, BPF_ANY);

		// Reset the buffer.
		memset(buffer, 0, COMMAND_SCRATCH_SIZE);

		// Copy image path into the LRU hash.  Note we use IMAGE_PATH_SIZE - 1 to leave a guaranteed null terminator
		bpf_process_get_image_path(ctx, buffer, IMAGE_PATH_SIZE - 1);
		bpf_map_update_elem(&process_map, &process_create_info.process_id, buffer, BPF_ANY);
		bpf_ringbuf_output(&process_ringbuf, &process_create_info, sizeof(process_create_info), 0);

	} else if (ctx->operation == PROCESS_OPERATION_DELETE) {
		struct process_exit_info_t process_exit_info;

		memset(&process_exit_info, 0, sizeof(process_exit_info));
		process_exit_info.process_id = ctx->process_id;
		process_exit_info.common.ktime = ctx->exit_time;
		process_exit_info.exit_time = ctx->exit_time;
		process_exit_info.process_exit_code = ctx->process_exit_code;
		process_exit_info.common.op = MSG_OP_EXIT;
		bpf_ringbuf_output(&process_ringbuf, &process_exit_info, sizeof(process_exit_info), 0);
	}
	return 0;
}
