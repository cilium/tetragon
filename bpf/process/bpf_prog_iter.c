// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "bpf_helpers.h"

SEC("iter/bpf_prog")
int iter(struct bpf_iter__bpf_prog *ctx)
{
	struct bpf_prog *prog = ctx->prog;
	__u32 id;

	if (!prog)
		return 0;

	_(id = prog->aux->id);
	seq_write(ctx->meta->seq, &id, sizeof(id));
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
