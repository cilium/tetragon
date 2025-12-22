// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __GENERIC_CALLS_H__
#define __GENERIC_CALLS_H__

#include "bpf_tracing.h"
#include "pfilter.h"
#include "policy_filter.h"
#include "types/basic.h"
#include "vmlinux.h"
#include "policy_conf.h"
#include "policy_stats.h"
#include "generic_path.h"
#include "bpf_ktime.h"
#include "regs.h"

#define MAX_TOTAL 9000

FUNC_INLINE int
generic_start_process_filter(void *ctx, struct bpf_map_def *calls)
{
	struct msg_generic_kprobe *msg;
	struct event_config *config;
	struct task_struct *task;
	int i, zero = 0;

	msg = map_lookup_elem(&process_call_heap, &zero);
	if (!msg)
		return 0;

	/* setup index, check policy filter, and setup function id */
	msg->idx = get_index(ctx);
	config = map_lookup_elem(&config_map, &msg->idx);
	if (!config)
		return 0;
	if (!policy_filter_check(config->policy_id))
		return 0;
	msg->func_id = config->func_id;
	msg->retprobe_id = 0;

	/* Initialize selector index to 0 */
	msg->sel.curr = 0;
#pragma unroll
	for (i = 0; i < MAX_CONFIGURED_SELECTORS; i++)
		msg->sel.active[i] = 0;
	/* Initialize accept field to reject */
	msg->sel.pass = false;
	msg->tailcall_index_process = 0;
	msg->tailcall_index_selector = 0;
	generic_path_init(msg);
	task = (struct task_struct *)get_current_task();
	/* Initialize namespaces to apply filters on them */
	get_namespaces(&msg->ns, task);
	/* Initialize capabilities to apply filters on them */
	get_current_subj_caps(&msg->caps, task);
#ifdef __NS_CHANGES_FILTER
	msg->sel.match_ns = 0;
#endif
#ifdef __CAP_CHANGES_FILTER
	msg->sel.match_cap = 0;
#endif

	msg->lsm.post = false;
	msg->common.flags = 0;

	/* Tail call into filters. */
	tail_call(ctx, calls, TAIL_CALL_FILTER);
	return 0;
}

FUNC_INLINE long
__copy_char_buf(void *ctx, long off, unsigned long arg, unsigned long bytes,
		bool max_data, struct msg_generic_kprobe *e)
{
	int *s = (int *)args_off(e, off);
	size_t rd_bytes, extra = 8;
	int err;

#ifdef __LARGE_BPF_PROG
	if (max_data && data_heap_ptr) {
		/* The max_data flag is enabled, the first int value indicates
		 * if we use (1) data events or not (0).
		 */
		if (bytes >= 0x1000) {
			s[0] = 1;
			return data_event_bytes(ctx,
						(struct data_event_desc *)&s[1],
						arg, bytes, data_heap_ptr) +
			       4;
		}
		s[0] = 0;
		s = (int *)args_off(e, off + 4);
		extra += 4;
	}
#endif // __LARGE_BPF_PROG

	/* Bound bytes <4095 to ensure bytes does not read past end of buffer */
	rd_bytes = bytes < 0x1000 ? bytes : 0xfff;
	asm volatile("%[rd_bytes] &= 0xfff;\n"
		     : [rd_bytes] "+r"(rd_bytes));
	err = probe_read(&s[2], rd_bytes, (char *)arg);
	if (err < 0)
		return return_error(s, char_buf_pagefault);
	s[0] = (int)bytes;
	s[1] = (int)rd_bytes;
	return rd_bytes + extra;
}

FUNC_INLINE long
copy_char_buf(void *ctx, long off, unsigned long arg, int argm,
	      struct msg_generic_kprobe *e)
{
	int *s = (int *)args_off(e, off);
	unsigned long meta;
	size_t bytes = 0;

	if (has_return_copy(argm)) {
		u64 retid = retprobe_map_get_key(ctx);

		retprobe_map_set(e->func_id, retid, e->common.ktime, arg);
		return return_error(s, char_buf_saved_for_retprobe);
	}
	meta = get_arg_meta(argm, e);
	probe_read(&bytes, sizeof(bytes), &meta);
	return __copy_char_buf(ctx, off, arg, bytes, has_max_data(argm), e);
}

#ifdef __LARGE_BPF_PROG
FUNC_INLINE long
copy_iov_iter(void *ctx, long off, unsigned long arg, int argm, struct msg_generic_kprobe *e)
{
	long iter_iovec = -1, iter_ubuf __maybe_unused = -1;
	struct iov_iter *iov_iter = (struct iov_iter *)arg;
	struct kvec *kvec;
	const char *buf;
	size_t count;
	u8 iter_type;
	void *tmp;
	int *s;

	if (!bpf_core_field_exists(iov_iter->iter_type))
		goto nodata;

	tmp = _(&iov_iter->iter_type);
	probe_read(&iter_type, sizeof(iter_type), tmp);

	if (bpf_core_enum_value_exists(enum iter_type, ITER_IOVEC))
		iter_iovec = bpf_core_enum_value(enum iter_type, ITER_IOVEC);

#ifdef __V61_BPF_PROG
	if (bpf_core_enum_value_exists(enum iter_type, ITER_UBUF))
		iter_ubuf = bpf_core_enum_value(enum iter_type, ITER_UBUF);
#endif

	if (iter_type == iter_iovec) {
		tmp = _(&iov_iter->kvec);
		probe_read(&kvec, sizeof(kvec), tmp);

		tmp = _(&kvec->iov_base);
		probe_read(&buf, sizeof(buf), tmp);

		tmp = _(&kvec->iov_len);
		probe_read(&count, sizeof(count), tmp);

		return __copy_char_buf(ctx, off, (unsigned long)buf, count,
				       has_max_data(argm), e);
	}

#ifdef __V61_BPF_PROG
	if (iter_type == iter_ubuf) {
		tmp = _(&iov_iter->ubuf);
		probe_read(&buf, sizeof(buf), tmp);

		tmp = _(&iov_iter->count);
		probe_read(&count, sizeof(count), tmp);

		return __copy_char_buf(ctx, off, (unsigned long)buf, count,
				       has_max_data(argm), e);
	}
#endif

nodata:
	s = (int *)args_off(e, off);
	s[0] = 0;
	s[1] = 0;
	return 8;
}
#else
#define copy_iov_iter(ctx, orig_off, arg, argm, e) 0
#endif /* __LARGE_BPF_PROG */

/**
 * Read a generic argument
 *
 * @args: destination buffer for the generic argument
 * @type: type of the argument
 * @off: offset of the argument within @args
 * @arg: argument location (generally, address of the argument)
 * @argm: argument metadata. The meaning of this depends on the @type. Some
 *        types use a -1 to designate saving @arg into the retprobe map
 * @filter_map:
 *
 * Returns the size of data appended to @args.
 */
FUNC_INLINE long
read_arg(void *ctx, int index, int type, long orig_off, unsigned long arg, int argm)
{
	size_t min_size = type_to_min_size(type, argm);
	struct msg_generic_kprobe *e;
	char *args;
	long size = -1;
	const struct path *path_arg = 0;
	struct path path_buf;
	int zero = 0;

	e = map_lookup_elem(&process_call_heap, &zero);
	if (!e)
		return 0;

	if (orig_off >= 16383 - min_size)
		return 0;

	orig_off &= 16383;
	args = args_off(e, orig_off);

	/* Cache args offset for filter use later */
	e->argsoff[index & MAX_SELECTORS_MASK] = orig_off;

	path_arg = get_path(type, arg, &path_buf);
	if (path_arg)
		return copy_path(args, path_arg);

	switch (type) {
	case iov_iter_type:
		size = copy_iov_iter(ctx, orig_off, arg, argm, e);
		break;
	case fd_ty: {
		struct fdinstall_key key = { 0 };
		struct fdinstall_value *val;
		__u32 fd;

		key.tid = get_current_pid_tgid() >> 32;
		probe_read(&fd, sizeof(__u32), &arg);
		key.fd = fd;

		val = map_lookup_elem(&fdinstall_map, &key);
		if (val) {
			__u32 bytes = *((__u32 *)&val->file[0]);

			probe_read(&args[0], sizeof(__u32), &fd);
			asm volatile("%[bytes] &= 0xfff;\n"
				     : [bytes] "+r"(bytes)
				     :);
			probe_read(&args[4], bytes + 4, (char *)&val->file[0]);
			size = bytes + 4 + 4;

			// flags
			probe_read(&args[size], 4,
				   (char *)&val->file[size - 4]);
			size += 4;
		} else {
			/* If filter specification is fd type then we
			 * expect the fd has been previously followed
			 * otherwise drop the event.
			 */
			return -1;
		}
	} break;
	case filename_ty: {
		struct filename *file;

		probe_read(&file, sizeof(file), &arg);
		probe_read(&arg, sizeof(arg), &file->name);
	}
		fallthrough;
	case string_type:
		size = copy_strings(args, (char *)arg, MAX_STRING);
		break;
	case net_dev_ty: {
		struct net_device *dev = (struct net_device *)arg;

		size = copy_strings(args, dev->name, IFNAMSIZ);
	} break;
	case data_loc_type: {
		// data_loc: lower 16 bits is offset from ctx; upper 16 bits is length
		long dl_len = (arg >> 16) & 0xfff; // masked to 4095 chars
		char *dl_loc = ctx + (arg & 0xffff);

		size = copy_strings(args, dl_loc, dl_len);
	} break;
	case syscall64_type:
	case size_type:
	case s64_ty:
	case u64_ty:
		probe_read(args, sizeof(__u64), &arg);
		size = sizeof(__u64);
		break;
	/* Consolidate all the types to save instructions */
	case int_type:
	case s32_ty:
	case u32_ty:
		probe_read(args, sizeof(__u32), &arg);
		size = sizeof(__u32);
		break;
	case s16_ty:
	case u16_ty:
		/* read 2 bytes, but send 4 to keep alignment */
		probe_read(args, sizeof(__u16), &arg);
		size = sizeof(__u32);
		break;
	case s8_ty:
	case u8_ty:
		/* read 1 byte, but send 4 to keep alignment */
		probe_read(args, sizeof(__u8), &arg);
		size = sizeof(__u32);
		break;
	case skb_type:
		size = copy_skb(args, arg);
		break;
	case sock_type:
		size = copy_sock(args, arg);
		// Look up socket in our sock->pid_tgid map
		update_pid_tid_from_sock(e, arg);
		break;
	case sockaddr_type:
		size = copy_sockaddr(args, arg);
		break;
	case socket_type:
		size = copy_socket(args, arg);
		// Look up socket in our sock->pid_tgid map
		update_pid_tid_from_sock(e, ((struct sk_type *)args)->sockaddr);
		break;
	case cred_type:
		size = copy_cred(args, arg);
		break;
	case char_buf:
		size = copy_char_buf(ctx, orig_off, arg, argm, e);
		break;
	case char_iovec:
		size = copy_char_iovec(ctx, orig_off, arg, argm, e);
		break;
	case const_buf_type: {
		// bound size to 1023 to help the verifier out
		size = argm & 0x03ff;
		probe_read(args, size, (char *)arg);
		break;
	}
	case bpf_attr_type: {
		size = copy_bpf_attr(args, arg);
		break;
	}
	case bpf_prog_type: {
		size = copy_bpf_prog(args, arg);
		break;
	}
	case perf_event_type: {
		size = copy_perf_event(args, arg);
		break;
	}
	case bpf_map_type: {
		size = copy_bpf_map(args, arg);
		break;
	}
	case user_namespace_type: {
		size = copy_user_ns(args, arg);
		break;
	}
	case capability_type: {
		size = copy_capability(args, arg);
		break;
	}
	case load_module_type: {
		size = copy_load_module(args, arg);
		break;
	}
	case kernel_module_type: {
		size = copy_kernel_module(args, arg);
		break;
	}
	case kernel_cap_ty:
	case cap_inh_ty:
	case cap_prm_ty:
	case cap_eff_ty:
		probe_read(args, sizeof(__u64), (char *)arg);
		size = sizeof(__u64);
		break;
	case int32_arr_type: {
		if (has_return_copy(argm)) {
			u64 retid = retprobe_map_get_key(ctx);

			retprobe_map_set(e->func_id, retid, e->common.ktime, arg);
			return return_error((int *)args, char_buf_saved_for_retprobe);
		}
		__u32 count = (argm >> 8) & 0xffff;
		if (count > MAX_FILTER_INT_ARGS)
			count = MAX_FILTER_INT_ARGS;
		probe_read(args, sizeof(__u32), &count);
		probe_read(args + sizeof(__u32), count * sizeof(__u32), (void *)arg);
		size = sizeof(__u32) + count * sizeof(__u32);
	} break;
	default:
		size = 0;
		break;
	}
	return size;
}

FUNC_INLINE int
extract_arg_depth(u32 i, struct extract_arg_data *data)
{
	if (i >= MAX_BTF_ARG_DEPTH || !data->btf_config[i].is_initialized)
		return 1;
	*data->arg = *data->arg + data->btf_config[i].offset;
	if (data->btf_config[i].is_pointer)
		probe_read((void *)data->arg, sizeof(char *), (void *)*data->arg);
	return 0;
}

#ifdef __LARGE_BPF_PROG
FUNC_INLINE void extract_arg(struct event_config *config, int index, unsigned long *a)
{
	struct config_btf_arg *btf_config;

	if (index >= EVENT_CONFIG_MAX_ARG)
		return;

	asm volatile("%[index] &= %1 ;\n"
		     : [index] "+r"(index)
		     : "i"(MAX_SELECTORS_MASK));
	btf_config = config->btf_arg[index];
	if (btf_config->is_initialized) {
		struct extract_arg_data extract_data = {
			.btf_config = btf_config,
			.arg = a,
		};
#ifndef __V61_BPF_PROG
#pragma unroll
		for (int i = 0; i < MAX_BTF_ARG_DEPTH; ++i) {
			if (extract_arg_depth(i, &extract_data))
				break;
		}
#else
		loop(MAX_BTF_ARG_DEPTH, extract_arg_depth, &extract_data, 0);
#endif /* __V61_BPF_PROG */
	}
}
#else
FUNC_INLINE void extract_arg(struct event_config *config, int index, unsigned long *a) {}
#endif /* __LARGE_BPF_PROG */

FUNC_INLINE int arg_idx(int index)
{
	struct msg_generic_kprobe *e;
	struct event_config *config;
	int zero = 0;

	e = map_lookup_elem(&process_call_heap, &zero);
	if (!e)
		return -1;

	config = map_lookup_elem(&config_map, &e->idx);
	if (!config)
		return -1;

	asm volatile("%[index] &= %1 ;\n"
		     : [index] "+r"(index)
		     : "i"(MAX_SELECTORS_MASK));
	return config->idx[index];
}

FUNC_INLINE long get_pt_regs_arg_syscall(struct pt_regs *ctx, __u16 offset, __u8 shift)
{
	void *_ctx;
	long val;

	_ctx = PT_REGS_SYSCALL_REGS(ctx);
	if (!_ctx)
		return 0;

	probe_read(&val, sizeof(val), _ctx + offset);
	val <<= shift;
	val >>= shift;
	return val;
}

// TODO let's unite this with read_reg in bpf/process/uprobe_offload.h
#if defined(__TARGET_ARCH_x86) && (defined GENERIC_KPROBE || defined GENERIC_UPROBE)
FUNC_INLINE long get_pt_regs_arg(struct pt_regs *ctx, struct event_config *config, int index)
{
	struct config_reg_arg *reg;
	__u8 shift;

	asm volatile("%[index] &= %1 ;\n"
		     : [index] "+r"(index)
		     : "i"(MAX_SELECTORS_MASK));
	reg = &config->reg_arg[index];
	shift = 64 - reg->size * 8;

	if (config->syscall)
		return get_pt_regs_arg_syscall(ctx, reg->offset, shift);

	return read_reg(ctx, reg->offset, shift);
}
#else
FUNC_INLINE long get_pt_regs_arg(struct pt_regs *ctx, struct event_config *config, int index)
{
	return 0;
}
#endif /* __TARGET_ARCH_x86 && (GENERIC_KPROBE || GENERIC_UPROBE) */

FUNC_INLINE long generic_read_arg(void *ctx, int index, long off, struct bpf_map_def *tailcals)
{
	struct msg_generic_kprobe *e;
	struct event_config *config;
	int am, zero = 0, arg_index __maybe_unused;
	unsigned long a;
	long ty;

	e = map_lookup_elem(&process_call_heap, &zero);
	if (!e)
		return 0;

	config = map_lookup_elem(&config_map, &e->idx);
	if (!config)
		return 0;

	asm volatile("%[index] &= %1 ;\n"
		     : [index] "+r"(index)
		     : "i"(MAX_SELECTORS_MASK));
	ty = config->arg[index];
	am = config->arm[index];

#if defined(GENERIC_TRACEPOINT) || defined(GENERIC_USDT)
	a = (&e->a0)[index];
	extract_arg(config, index, &a);
#else
	arg_index = config->idx[index];
	asm volatile("%[arg_index] &= %1 ;\n"
		     : [arg_index] "+r"(arg_index)
		     : "i"(MAX_SELECTORS_MASK));

	/* Getting argument data based on the source attribute, which is encoded
	 * in argument meta data, so far it's either:
	 *
	 *   - pt_regs register
	 *   - current task object
	 *   - real argument value
	 */
	if (am & ARGM_PT_REGS)
		a = get_pt_regs_arg(ctx, config, arg_index);
	else if (am & ARGM_CURRENT_TASK)
		a = get_current_task();
	else
		a = (&e->a0)[arg_index];

	extract_arg(config, index, &a);

	if (should_offload_path(ty))
		return generic_path_offload(ctx, ty, a, index, off, tailcals);
#endif

	return read_arg(ctx, index, ty, off, a, am);
}

FUNC_INLINE int
generic_process_event(void *ctx, struct bpf_map_def *tailcals)
{
	struct msg_generic_kprobe *e;
	int index, zero = 0;
	long total;

	e = map_lookup_elem(&process_call_heap, &zero);
	if (!e)
		return 0;

	index = e->tailcall_index_process;
	total = e->common.size;

	/* Read out args1-5 */
	if (total < MAX_TOTAL) {
		long errv;

		errv = generic_read_arg(ctx, index, total, tailcals);
		if (errv > 0)
			total += errv;
		/* Follow filter lookup failed so lets abort the event.
		 * From high-level this is a filter and should be in the
		 * filter block, but its just easier to do here so lets
		 * do it where it makes most sense.
		 */
		if (errv < 0)
			return filter_args_reject(e->func_id);
	}
	e->common.size = total;
	/* Continue to process other arguments. */
	if (index < 4 && arg_idx(index + 1) != -1) {
		e->tailcall_index_process = index + 1;
		tail_call(ctx, tailcals, TAIL_CALL_PROCESS);
	}

	/* Last argument, go send.. */
	e->tailcall_index_process = 0;
	tail_call(ctx, tailcals, TAIL_CALL_ARGS);
	return 0;
}

FUNC_INLINE void
generic_process_init(struct msg_generic_kprobe *e, u8 op)
{
	e->common.op = op;

	e->common.pad[0] = 0;
	e->common.pad[1] = 0;
	e->common.size = 0;
	e->common.ktime = tg_get_ktime();

	e->current.pad[0] = 0;
	e->current.pad[1] = 0;
	e->current.pad[2] = 0;
	e->current.pad[3] = 0;

	e->action = 0;

	/**
	 * Per thread tracking rules TID is the calling thread:
	 *  At kprobes, tracpoints etc we report the calling thread ID to user space.
	 */
	e->tid = (__u32)get_current_pid_tgid();
}

#ifdef GENERIC_USDT
FUNC_INLINE unsigned long
read_usdt_arg(struct pt_regs *ctx, struct event_config *config, int index)
{
	struct config_usdt_arg *arg;
	unsigned long val, off, idx;
	int err;

	index &= 7;
	arg = &config->usdt_arg[index];

	if (arg->type == USDT_ARG_TYPE_NONE)
		return 0;

	switch (arg->type) {
	case USDT_ARG_TYPE_CONST:
		/* Arg is just a constant ("-4@$-9" in USDT arg spec).
		 * value is recorded in arg->val_off directly.
		 */
		val = arg->val_off;
		break;
	case USDT_ARG_TYPE_REG:
		/* Arg is in a register (e.g, "8@%rax" in USDT arg spec),
		 * so we read the contents of that register directly from
		 * struct pt_regs. To keep things simple user-space parts
		 * record offsetof(struct pt_regs, <regname>) in arg->reg_off.
		 */
		off = arg->reg_off & 0xfff;
		err = probe_read_kernel(&val, sizeof(val), (void *)ctx + off);
		if (err)
			return 0;
		break;
	case USDT_ARG_TYPE_REG_DEREF:
		/* Arg is in memory addressed by register, plus some offset
		 * (e.g., "-4@-1204(%rbp)" in USDT arg spec). Register is
		 * identified like with BPF_USDT_ARG_REG case, and the offset
		 * is in arg->val_off. We first fetch register contents
		 * from pt_regs, then do another user-space probe read to
		 * fetch argument value itself.
		 */
		off = arg->reg_off & 0xfff;
		err = probe_read_kernel(&val, sizeof(val), (void *)ctx + off);
		if (err)
			return err;
		err = probe_read_user(&val, sizeof(val), (void *)val + arg->val_off);
		if (err)
			return err;
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
		val >>= arg->shift;
#endif
		break;
	case USDT_ARG_TYPE_SIB:
		/* Arg is in memory addressed by SIB (Scale-Index-Base) mode
		 * (e.g., "-1@-96(%rbp,%rax,8)" in USDT arg spec). We first
		 * fetch the base register contents and the index register
		 * contents from pt_regs. Then we calculate the final address
		 * as base + (index * scale) + offset, and do a user-space
		 * probe read to fetch the argument value.
		 */
		off = arg->reg_off & 0xfff;
		err = probe_read_kernel(&val, sizeof(val), (void *)ctx + off);
		if (err)
			return err;
		off = arg->reg_idx_off & 0xfff;
		err = probe_read_kernel(&idx, sizeof(idx), (void *)ctx + off);
		if (err)
			return err;
		err = probe_read_user(&val, sizeof(val), (void *)(val + (idx << arg->scale) + arg->val_off));
		if (err)
			return err;
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
		val >>= arg_spec->arg_bitshift;
#endif
		break;
	default:
		return 0;
	}

	/* cast arg from 1, 2, or 4 bytes to final 8 byte size clearing
	 * necessary upper arg_bitshift bits, with sign extension if argument
	 * is signed
	 */
	val <<= arg->shift;
	if (arg->sig)
		val = ((long)val) >> arg->shift;
	else
		val = val >> arg->shift;
	return val;
}
#endif /* GENERIC_USDT */

FUNC_INLINE int
generic_process_event_and_setup(struct pt_regs *ctx, struct bpf_map_def *tailcals)
{
	struct msg_generic_kprobe *e;
	struct event_config *config;
	int zero = 0;
	long ty __maybe_unused;

	/* Pid/Ktime Passed through per cpu map in process heap. */
	e = map_lookup_elem(&process_call_heap, &zero);
	if (!e)
		return 0;

	config = map_lookup_elem(&config_map, &e->idx);
	if (!config)
		return 0;

#ifdef GENERIC_KPROBE
	if (config->syscall) {
		struct pt_regs *_ctx;
		_ctx = PT_REGS_SYSCALL_REGS(ctx);
		if (!_ctx)
			return 0;
		e->a0 = PT_REGS_PARM1_CORE_SYSCALL(_ctx);
		e->a1 = PT_REGS_PARM2_CORE_SYSCALL(_ctx);
		e->a2 = PT_REGS_PARM3_CORE_SYSCALL(_ctx);
		e->a3 = PT_REGS_PARM4_CORE_SYSCALL(_ctx);
		e->a4 = PT_REGS_PARM5_CORE_SYSCALL(_ctx);
	} else {
		e->a0 = PT_REGS_PARM1_CORE(ctx);
		e->a1 = PT_REGS_PARM2_CORE(ctx);
		e->a2 = PT_REGS_PARM3_CORE(ctx);
		e->a3 = PT_REGS_PARM4_CORE(ctx);
		e->a4 = PT_REGS_PARM5_CORE(ctx);
	}

	generic_process_init(e, MSG_OP_GENERIC_KPROBE);

	e->retprobe_id = retprobe_map_get_key(ctx);

	/* If return arg is needed mark retprobe */
	ty = config->argreturn;
	if (ty > 0)
		retprobe_map_set(e->func_id, e->retprobe_id, e->common.ktime, 1);
#endif

#ifdef GENERIC_LSM
	struct bpf_raw_tracepoint_args *raw_args = (struct bpf_raw_tracepoint_args *)ctx;

	e->a0 = BPF_CORE_READ(raw_args, args[0]);
	e->a1 = BPF_CORE_READ(raw_args, args[1]);
	e->a2 = BPF_CORE_READ(raw_args, args[2]);
	e->a3 = BPF_CORE_READ(raw_args, args[3]);
	e->a4 = BPF_CORE_READ(raw_args, args[4]);
	generic_process_init(e, MSG_OP_GENERIC_LSM);
#endif

#ifdef GENERIC_UPROBE
	e->a0 = PT_REGS_PARM1_CORE(ctx);
	e->a1 = PT_REGS_PARM2_CORE(ctx);
	e->a2 = PT_REGS_PARM3_CORE(ctx);
	e->a3 = PT_REGS_PARM4_CORE(ctx);
	e->a4 = PT_REGS_PARM5_CORE(ctx);
	generic_process_init(e, MSG_OP_GENERIC_UPROBE);

	e->retprobe_id = retprobe_map_get_key(ctx);

	/* If return arg is needed mark retprobe */
	ty = config->argreturn;
	if (ty > 0)
		retprobe_map_set(e->func_id, e->retprobe_id, e->common.ktime, 1);
#endif

#ifdef GENERIC_USDT
	generic_process_init(e, MSG_OP_GENERIC_USDT);
#endif

#ifdef GENERIC_RAWTP
	struct bpf_raw_tracepoint_args *raw_args = (struct bpf_raw_tracepoint_args *)ctx;

	e->a0 = BPF_CORE_READ(raw_args, args[0]);
	e->a1 = BPF_CORE_READ(raw_args, args[1]);
	e->a2 = BPF_CORE_READ(raw_args, args[2]);
	e->a3 = BPF_CORE_READ(raw_args, args[3]);
	e->a4 = BPF_CORE_READ(raw_args, args[4]);
	generic_process_init(e, MSG_OP_GENERIC_TRACEPOINT);
#endif

#ifdef GENERIC_USDT
	e->a0 = read_usdt_arg(ctx, config, 0);
	e->a1 = read_usdt_arg(ctx, config, 1);
	e->a2 = read_usdt_arg(ctx, config, 2);
	e->a3 = read_usdt_arg(ctx, config, 3);
	e->a4 = read_usdt_arg(ctx, config, 4);
#endif

	/* No arguments, go send.. */
	if (arg_idx(0) == -1)
		tail_call(ctx, tailcals, TAIL_CALL_ARGS);

	tail_call(ctx, tailcals, TAIL_CALL_PROCESS);
	return 0;
}

#if defined GENERIC_KPROBE || defined GENERIC_LSM
FUNC_INLINE void
do_override_action(__s32 error)
{
	__s32 *error_p;
	__u64 id;

	id = get_current_pid_tgid();

	/*
	 * TODO: this should not happen, it means that the override
	 * program was not executed for some reason, we should do
	 * warning in here
	 */
	error_p = map_lookup_elem(&override_tasks, &id);
	if (error_p)
		*error_p = error;
	else
		map_update_elem(&override_tasks, &id, &error, BPF_ANY);
}
#else
#define do_override_action(error)
#endif

#if defined GENERIC_USDT
#ifdef __V61_BPF_PROG
FUNC_INLINE int
write_user_arg(void *ctx, void *addr, __u32 value)
{
	struct write_offload_data *data, tmp = {
		.addr = (unsigned long)addr,
		.value = value,

	};
	__u64 id = get_current_pid_tgid();

	/*
	 * TODO: this should not happen, it means that the override
	 * program was not executed for some reason, we should do
	 * warning in here
	 */
	data = map_lookup_elem(&write_offload, &id);
	if (data)
		*data = tmp;
	else
		map_update_elem(&write_offload, &id, &tmp, BPF_ANY);

	return 0;
}
#else
FUNC_INLINE int
write_user_arg(void *ctx, void *addr, __u32 value)
{
	return probe_write_user(addr, &value, sizeof(value));
}
#endif

FUNC_INLINE void
do_set_action(void *ctx, struct msg_generic_kprobe *e, __u32 arg_idx, __u32 arg_value)
{
	struct config_usdt_arg *arg;
	struct event_config *config;
	unsigned long val, off;
	int err = -1;

	config = map_lookup_elem(&config_map, &e->idx);
	if (!config)
		return;

	arg_idx &= 7;
	arg = &config->usdt_arg[arg_idx];

	switch (arg->type) {
	case USDT_ARG_TYPE_NONE:
	case USDT_ARG_TYPE_CONST:
	case USDT_ARG_TYPE_REG:
	case USDT_ARG_TYPE_SIB:
		break;
	case USDT_ARG_TYPE_REG_DEREF:
		off = arg->reg_off & 0xfff;
		err = probe_read_kernel(&val, sizeof(val), (void *)ctx + off);
		if (err)
			return;
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
		arg_value <<= arg->shift;
#endif
		err = write_user_arg(ctx, (void *)val + arg->val_off, arg_value);
		break;
	}

	if (err)
		e->common.flags |= MSG_COMMON_FLAG_ACTION_FAILED;
}
#else
#define do_set_action(ctx, idx, arg_idx, arg_value)
#endif

FUNC_LOCAL __u32
do_action(void *ctx, __u32 i, struct selector_action *actions, bool *post, bool enforce_mode)
{
	__u32 index __maybe_unused, value __maybe_unused;
	int signal __maybe_unused = FGS_SIGKILL;
	int action = actions->act[i];
	struct msg_generic_kprobe *e;
	__s32 error __maybe_unused;
	int fdi, namei;
	int newfdi, oldfdi;
	int socki;
	int argi __maybe_unused;
	int err = 0;
	int zero = 0;
	u32 polacct;

	e = map_lookup_elem(&process_call_heap, &zero);
	if (!e)
		return 0;

	polacct = POLICY_INVALID_ACT_;
	switch (action) {
	case ACTION_NOPOST:
		*post = false;
		break;
	case ACTION_POST: {
		__u64 ratelimit_interval __maybe_unused = actions->act[++i];
		__u64 ratelimit_scope __maybe_unused = actions->act[++i];
#ifdef __LARGE_BPF_PROG
		if (rate_limit(ratelimit_interval, ratelimit_scope, e))
			*post = false;
#endif /* __LARGE_BPF_PROG */
		__u32 kernel_stack_trace = actions->act[++i];

		if (kernel_stack_trace) {
			// Stack id 0 is valid so we need a flag.
			e->common.flags |= MSG_COMMON_FLAG_KERNEL_STACKTRACE;
			// We could use BPF_F_REUSE_STACKID to override old with new stack if
			// same stack id. It means that if we have a collision and user space
			// reads the old one too late, we are reading the wrong stack (the new,
			// old one was overwritten).
			//
			// Here we just signal that there was a collision returning -EEXIST.
			e->kernel_stack_id = get_stackid(ctx, &stack_trace_map, 0);
		}

		__u32 user_stack_trace = actions->act[++i];

		if (user_stack_trace) {
			e->common.flags |= MSG_COMMON_FLAG_USER_STACKTRACE;
			e->user_stack_id = get_stackid(ctx, &stack_trace_map, BPF_F_USER_STACK);
		}
#ifdef __V511_BPF_PROG
		__u32 ima_hash = actions->act[++i];

		if (ima_hash)
			e->common.flags |= MSG_COMMON_FLAG_IMA_HASH;
#endif
		break;
	}

	case ACTION_UNFOLLOWFD:
	case ACTION_FOLLOWFD:
		fdi = actions->act[++i];
		namei = actions->act[++i];
		err = installfd(e, fdi, namei, action == ACTION_FOLLOWFD);
		break;
	case ACTION_COPYFD:
		oldfdi = actions->act[++i];
		newfdi = actions->act[++i];
		err = copyfd(e, oldfdi, newfdi);
		break;
	case ACTION_SIGNAL:
		signal = actions->act[++i];
		fallthrough;
	case ACTION_SIGKILL:
		if (enforce_mode) {
			do_action_signal(signal);
			polacct = POLICY_SIGNAL;
		} else {
			polacct = POLICY_MONITOR_SIGNAL;
		}
		break;
	case ACTION_OVERRIDE:
		error = actions->act[++i];
		if (enforce_mode) {
#if defined(GENERIC_UPROBE) && defined(__TARGET_ARCH_x86)
			do_uprobe_override(ctx, error);
#else
			do_override_action(error);
#endif
			polacct = POLICY_OVERRIDE;
		} else {
			polacct = POLICY_MONITOR_OVERRIDE;
		}
		break;
	case ACTION_GETURL:
	case ACTION_DNSLOOKUP:
		/* Set the URL or DNS action */
		e->action_arg_id = actions->act[++i];
		break;
	case ACTION_TRACKSOCK:
	case ACTION_UNTRACKSOCK:
		socki = actions->act[++i];
		err = tracksock(e, socki, action == ACTION_TRACKSOCK);
		break;
	case ACTION_NOTIFY_ENFORCER:
		error = actions->act[++i];
		signal = actions->act[++i];
		argi = actions->act[++i];
		if (enforce_mode) {
			do_action_notify_enforcer(e, error, signal, argi);
			polacct = POLICY_NOTIFY_ENFORCER;
		} else {
			polacct = POLICY_MONITOR_NOTIFY_ENFORCER;
		}
		break;
	case ACTION_CLEANUP_ENFORCER_NOTIFICATION:
		do_enforcer_cleanup();
		break;
	case ACTION_SET:
		index = actions->act[++i];
		value = actions->act[++i];
		do_set_action(ctx, e, index, value);
		break;
	default:
		break;
	}

	if (polacct != POLICY_INVALID_ACT_) {
		policy_stats_update(polacct);
	}

	if (!err) {
		e->action = action;
		return ++i;
	}
	return 0;
}

FUNC_INLINE bool
has_action(struct selector_action *actions, __u32 idx)
{
	__u32 offset = idx * sizeof(__u32) + sizeof(*actions);

	return offset < actions->actionlen;
}

/* Currently supporting 2 actions for selector. */
FUNC_INLINE bool
do_actions(void *ctx, struct selector_action *actions)
{
	bool post = true;
	__u32 l, i = 0, zero = 0;
	struct policy_conf *pcnf;
	bool enforce_mode = true;

	/* check if policy is in monitor (non-enforcement) mode and, if it is, skip enforcement
	 * actions
	 */
	pcnf = map_lookup_elem(&policy_conf, &zero);
	if (pcnf && pcnf->mode != POLICY_MODE_ENFORCE)
		enforce_mode = false;

#ifndef __LARGE_BPF_PROG
#pragma unroll
#endif
	for (l = 0; l < MAX_ACTIONS; l++) {
		if (!has_action(actions, i))
			break;
		i = do_action(ctx, i, actions, &post, enforce_mode);
	}

	return post;
}

FUNC_INLINE long
generic_actions(void *ctx, struct bpf_map_def *calls)
{
	struct selector_arg_filters *arg;
	struct selector_action *actions;
	struct msg_generic_kprobe *e;
	int actoff, pass, zero = 0;
	bool postit;
	__u8 *f;

	e = map_lookup_elem(&process_call_heap, &zero);
	if (!e)
		return 0;

	pass = e->pass;
	if (pass <= 1)
		return 0;

	f = map_lookup_elem(&filter_map, &e->idx);
	if (!f)
		return 0;

	asm volatile("%[pass] &= 0x7ff;\n"
		     : [pass] "+r"(pass)
		     :);
	arg = (struct selector_arg_filters *)&f[pass];

	actoff = pass + arg->arglen;
	asm volatile("%[actoff] &= 0x7ff;\n"
		     : [actoff] "+r"(actoff)
		     :);
	actions = (struct selector_action *)&f[actoff];

	postit = do_actions(ctx, actions);
	if (postit)
		tail_call(ctx, calls, TAIL_CALL_SEND);
	return postit;
}

FUNC_INLINE long
generic_output(void *ctx, u8 op)
{
	struct msg_generic_kprobe *e;
	int zero = 0;
	size_t total;

	e = map_lookup_elem(&process_call_heap, &zero);
	if (!e)
		return 0;

/* We don't need this data in return kprobe event */
#if !defined(GENERIC_KRETPROBE) && !defined(GENERIC_URETPROBE)
#ifdef __NS_CHANGES_FILTER
	/* update the namespaces if we matched a change on that */
	if (e->sel.match_ns) {
		__u32 pid = (get_current_pid_tgid() >> 32);
		struct task_struct *task =
			(struct task_struct *)get_current_task();
		struct execve_map_value *enter = execve_map_get_noinit(
			pid); // we don't want to init that if it does not exist
		if (enter)
			get_namespaces(&enter->ns, task);
	}
#endif
#ifdef __CAP_CHANGES_FILTER
	/* update the capabilities if we matched a change on that */
	if (e->sel.match_cap) {
		__u32 pid = (get_current_pid_tgid() >> 32);
		struct task_struct *task =
			(struct task_struct *)get_current_task();
		struct execve_map_value *enter = execve_map_get_noinit(
			pid); // we don't want to init that if it does not exist
		if (enter)
			get_current_subj_caps(&enter->caps, task);
	}
#endif
#endif // !GENERIC_KRETPROBE && !GENERIC_URETPROBE

	total = e->common.size + generic_kprobe_common_size();
	/* Code movement from clang forces us to inline bounds checks here */
	asm volatile("%[total] &= 0x7fff;\n"
		     "if %[total] < 9000 goto +1\n;"
		     "%[total] = 9000;\n"
		     : [total] "+r"(total));
	event_output_metric(ctx, op, e, total);
	return 0;
}

FUNC_INLINE int generic_retprobe(void *ctx, struct bpf_map_def *calls, unsigned long ret)
{
	struct execve_map_value *enter;
	struct msg_generic_kprobe *e;
	struct retprobe_info info;
	struct event_config *config;
	bool walker = false;
	int zero = 0;
	__u32 ppid;
	long size = 0;
	long ty_arg, do_copy;
	__u64 pid_tgid;

	e = map_lookup_elem(&process_call_heap, &zero);
	if (!e)
		return 0;

	e->idx = get_index(ctx);

	config = map_lookup_elem(&config_map, &e->idx);
	if (!config)
		return 0;

	e->func_id = config->func_id;
	e->retprobe_id = retprobe_map_get_key(ctx);
	pid_tgid = get_current_pid_tgid();
	e->tid = (__u32)pid_tgid;

	if (!retprobe_map_get(e->func_id, e->retprobe_id, &info))
		return 0;

	*(unsigned long *)e->args = info.ktime_enter;
	size += sizeof(info.ktime_enter);

	ty_arg = config->argreturn;
	do_copy = config->argreturncopy;
	if (ty_arg) {
		size += read_arg(ctx, 0, ty_arg, size, ret, 0);
#if defined(__LARGE_BPF_PROG) && defined(GENERIC_KRETPROBE)
		struct socket_owner owner;

		switch (config->argreturnaction) {
		case ACTION_TRACKSOCK:
			owner.pid = e->current.pid;
			owner.tid = e->tid;
			owner.ktime = e->current.ktime;
			map_update_elem(&socktrack_map, &ret, &owner, BPF_ANY);
			break;
		case ACTION_UNTRACKSOCK:
			map_delete_elem(&socktrack_map, &ret);
			break;
		}
#endif
	}

	/*
	 * 0x1000 should be maximum argument length, so masking
	 * with 0x1fff is safe and verifier will be happy.
	 */
	asm volatile("%[size] &= 0x1fff;\n"
		     : [size] "+r"(size));

	switch (do_copy & 0xff) {
	case char_buf:
		size += __copy_char_buf(ctx, size, info.ptr, ret, false, e);
		break;
	case char_iovec:
		size += __copy_char_iovec(size, info.ptr, info.cnt, ret, e);
		break;
	case int32_arr_type: {
		char *args = args_off(e, size);
		__u32 count = (do_copy >> 8) & 0xffff;
		if (count > MAX_FILTER_INT_ARGS)
			count = MAX_FILTER_INT_ARGS;
		probe_read(args, sizeof(__u32), &count);
		probe_read(args + sizeof(__u32), count * sizeof(__u32), (void *)info.ptr);
		size += sizeof(__u32) + count * sizeof(__u32);
	} break;
	default:
		break;
	}

	/* Complete message header and send */
	enter = event_find_curr(&ppid, &walker);
#ifdef GENERIC_KRETPROBE
	e->common.op = MSG_OP_GENERIC_KPROBE;
#else
	e->common.op = MSG_OP_GENERIC_UPROBE;
#endif
	e->common.flags = MSG_COMMON_FLAG_RETURN;
	e->common.pad[0] = 0;
	e->common.pad[1] = 0;
	e->common.size = size;
	e->common.ktime = tg_get_ktime();

	if (enter) {
		e->current.pid = enter->key.pid;
		e->current.ktime = enter->key.ktime;
	}
	e->current.pad[0] = 0;
	e->current.pad[1] = 0;
	e->current.pad[2] = 0;
	e->current.pad[3] = 0;

	e->func_id = config->func_id;
	e->common.size = size;

	tail_call(ctx, calls, TAIL_CALL_ARGS);
	return 1;
}

// generic_process_filter performs first pass filtering based on pid/nspid.
// We keep a list of selectors that pass.
//
// if filter check was successful, it will return PFILTER_ACCEPT and properly
// set the values of:
//    current->pid
//    current->ktime
// for the memory located at index 0 of @msg_heap assuming the value follows the
// msg_generic_hdr structure.
FUNC_INLINE int generic_process_filter(void)
{
	int selectors, pass, zero = 0;
	struct execve_map_value *enter;
	struct msg_generic_kprobe *msg;
	struct msg_execve_key *current;
	struct msg_selector_data *sel;
	bool walker = 0;
	__u32 ppid, *f;

	msg = map_lookup_elem(&process_call_heap, &zero);
	if (!msg)
		return 0;

	enter = event_find_curr(&ppid, &walker);
	if (!enter) {
		enter = event_find_curr_probe(msg);
		if (!enter)
			return PFILTER_CURR_NOT_FOUND;
		msg->common.flags |= MSG_COMMON_FLAG_PROCESS_NOT_FOUND;
	}

	f = map_lookup_elem(&filter_map, &msg->idx);
	if (!f)
		return PFILTER_ERROR;

	sel = &msg->sel;
	current = &msg->current;

	if (sel->curr > MAX_SELECTORS)
		return process_filter_done(sel, enter, current);

	selectors = f[0];
	/* If no selectors accept process */
	if (!selectors) {
		sel->pass = true;
		return process_filter_done(sel, enter, current);
	}

	/* If we get here with reference to uninitialized selector drop */
	if (selectors <= sel->curr)
		return process_filter_done(sel, enter, current);

	pass = selector_process_filter(f, sel->curr, enter, msg);
	if (pass) {
		/* Verify lost that msg is not null here so recheck */
		int curr = sel->curr;

		asm volatile("%[curr] &= 0x1f;\n"
			     : [curr] "+r"(curr));
		sel->active[curr] = true;
		sel->active[SELECTORS_ACTIVE] = true;
		sel->pass |= true;
	}
	sel->curr++;
	if (sel->curr > selectors)
		return process_filter_done(sel, enter, current);
	return PFILTER_CONTINUE; /* will iterate to the next selector */
}

FUNC_INLINE int filter_args(struct msg_generic_kprobe *e, int selidx, bool is_entry)
{
	__u8 *f;

	/* No filters and no selectors so just accepts */
	f = map_lookup_elem(&filter_map, &e->idx);
	if (!f)
		return 1;

	/* No selectors, accept by default */
	if (!e->sel.active[SELECTORS_ACTIVE])
		return 1;

	/* We ran process filters early as a prefilter to drop unrelated
	 * events early. Now we need to ensure that active pid sselectors
	 * have their arg filters run.
	 */
	if (selidx > SELECTORS_ACTIVE)
		return filter_args_reject(e->func_id);

	if (e->sel.active[selidx]) {
		int pass = selector_arg_offset(f, e, selidx, is_entry);

		if (pass)
			return pass;
	}
	return 0;
}

_Static_assert(5 == MAX_SELECTORS, "update selidx_next()");
FUNC_INLINE int next_selidx(struct msg_generic_kprobe *e, int selidx)
{
	int idx = selidx + 1;

	switch (idx) {
	case 0:
		if (e->sel.active[idx & MAX_SELECTORS_MASK])
			break;
		idx++;
		fallthrough;
	case 1:
		if (e->sel.active[idx & MAX_SELECTORS_MASK])
			break;
		idx++;
		fallthrough;
	case 2:
		if (e->sel.active[idx & MAX_SELECTORS_MASK])
			break;
		idx++;
		fallthrough;
	case 3:
		if (e->sel.active[idx & MAX_SELECTORS_MASK])
			break;
		idx++;
		fallthrough;
	case 4:
		if (e->sel.active[idx & MAX_SELECTORS_MASK])
			break;
		idx++;
		fallthrough;
	case 5:
		if (e->sel.active[idx & MAX_SELECTORS_MASK])
			break;
		idx++;
	}

	return idx;
}

FUNC_INLINE long generic_filter_arg(void *ctx, struct bpf_map_def *tailcalls,
				    bool is_entry)
{
	struct msg_generic_kprobe *e;
	int selidx, pass, zero = 0;

	e = map_lookup_elem(&process_call_heap, &zero);
	if (!e)
		return 0;
	selidx = e->tailcall_index_selector;
	pass = filter_args(e, selidx & MAX_SELECTORS_MASK, is_entry);
	if (!pass) {
		selidx = next_selidx(e, selidx);
		if (selidx <= MAX_SELECTORS) {
			e->tailcall_index_selector = selidx;
			tail_call(ctx, tailcalls, TAIL_CALL_ARGS);
		}
		// reject if we did not attempt to tailcall, or if tailcall failed.
		return filter_args_reject(e->func_id);
	}

	// If pass >1 then we need to consult the selector actions
	// otherwise pass==1 indicates using default action.
	if (pass > 1) {
		e->pass = pass;
		tail_call(ctx, tailcalls, TAIL_CALL_ACTIONS);
	}

	tail_call(ctx, tailcalls, TAIL_CALL_SEND);
	return 0;
}
#endif /* __GENERIC_CALLS_H__ */
