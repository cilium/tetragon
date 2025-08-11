#ifndef __PFILTER_H__
#define __PFILTER_H__

/**
 * Process filters (see generic_process_filter)
 */

#define FIND_PIDSET(value, isns)                                          \
	{                                                                 \
		if (!filter)                                              \
			return 0;                                         \
		{                                                         \
			__u32 pid, ppid = 0;                              \
			if (isns) {                                       \
				pid = filter->nspid;                      \
			} else {                                          \
				pid = filter->key.pid;                    \
				ppid = filter->pkey.pid;                  \
			}                                                 \
			if (pid == value || ppid == value) {              \
				pidset_found = true;                      \
				goto accept;                              \
			}                                                 \
		}                                                         \
		filter = map_lookup_elem(&execve_map, &filter->pkey.pid); \
	}

#define FIND_PIDSET10(VAL, ISNS)       \
	{                              \
		FIND_PIDSET(VAL, ISNS) \
		FIND_PIDSET(VAL, ISNS) \
		FIND_PIDSET(VAL, ISNS) \
		FIND_PIDSET(VAL, ISNS) \
		FIND_PIDSET(VAL, ISNS) \
		FIND_PIDSET(VAL, ISNS) \
		FIND_PIDSET(VAL, ISNS) \
		FIND_PIDSET(VAL, ISNS) \
		FIND_PIDSET(VAL, ISNS) \
	}

#define FILTER_PIDSET(VAL)         \
	{                          \
		FIND_PIDSET10(VAL) \
	}

FUNC_INLINE bool
filter_pidset(__u64 sel, __u64 isns, struct execve_map_value *enter)
{
	struct execve_map_value *filter = enter;
	bool pidset_found = false;

	FIND_PIDSET10(sel, isns);
accept:
	return pidset_found;
}

#define PID_SELECTOR_FLAG_NSPID	 0x1
#define PID_SELECTOR_FLAG_FOLLOW 0x2

FUNC_INLINE bool
filter_pidsets(__u64 ty, __u64 flags, __u64 sel, struct execve_map_value *enter)
{
	bool found;
	__u64 isns = flags & PID_SELECTOR_FLAG_NSPID;

	/* If nspid rule and entry is not in a namespace drop it */
	if (isns && !enter->nspid)
		return 0;
	found = filter_pidset(sel, isns, enter);
	if (ty == op_filter_in && !found)
		return 0;
	else if (ty == op_filter_notin && found)
		return 0;
	return 1;
}

// generic_process_filter return value
enum {
	PFILTER_ERROR = 3, // these should never happen
	PFILTER_CONTINUE = 2, // filter check continue
	PFILTER_ACCEPT = 1, // filter check passed
	PFILTER_REJECT = 0, // filter check failed
	PFILTER_CURR_NOT_FOUND = 0, // event_find_curr() failed
};

FUNC_INLINE int
__process_filter_pid(__u64 ty, __u64 flags, __u64 sel, __u64 pid,
		     struct execve_map_value *enter)
{
	if (flags & PID_SELECTOR_FLAG_FOLLOW) {
		bool accept_pid = filter_pidsets(ty, flags, sel, enter);

		if (!accept_pid)
			return PFILTER_REJECT;
		return PFILTER_ACCEPT;
	} else {
		if (ty == op_filter_in && sel != pid)
			return PFILTER_REJECT;
		else if (ty == op_filter_notin && sel == pid)
			return PFILTER_REJECT;
		return PFILTER_ACCEPT;
	}
}

FUNC_INLINE int next_pid_value(__u32 off, __u32 *f, __u32 ty)
{
	return off + 4;
}

struct selector_filter {
	__u64 ty;
	__u64 flags;
	__u64 len;
	__u32 index;
};

enum {
	PF_CRED_UNKNOWN = 0x00, // No filter
	PF_CRED_RUID = 0x01, // Real UIDs
	PF_CRED_RGID = 0x02, // Real GIDs
	PF_CRED_EUID = 0x04, // Effective UIDs
};

struct cred_id {
	__u32 start;
	__u32 end;
} __attribute__((packed));

struct cred_filter {
	__u64 ty; /* credentials type flags */
	__u32 op; /* operator */
	__u32 num; /* number of values */
	struct cred_id val[];
} __attribute__((packed));

#define MAX_CRED_SELECTOR_FILTERS 2
#define MAX_CRED_SELECTOR_VALUES  3

/* counter field (4) + MAX_CRED_SELECTOR_FILTERS * size of cred_filter */
#define MAX_CRED_SIZE (((sizeof(struct cred_filter) +                           \
			 (MAX_CRED_SELECTOR_VALUES * sizeof(struct cred_id))) * \
			MAX_CRED_SELECTOR_FILTERS) +                            \
		       4)

#ifdef __LARGE_BPF_PROG

FUNC_INLINE int
__match_cred_uids(__u32 *f, __u32 *index, struct cred_filter *cred_f, __u32 uid)
{
	__u32 min, max;

	min = *(__u32 *)((__u64)f + (*index & INDEX_MASK));
	max = *(__u32 *)((__u64)f + ((*index + 4) & INDEX_MASK));
	if (cred_f->op == op_filter_eq && (uid >= min && uid <= max))
		return PFILTER_ACCEPT;
	else if (cred_f->op == op_filter_neq && (uid < min || uid > max))
		return PFILTER_ACCEPT;

	return PFILTER_REJECT;
}

/* match_cred_uids() parses passed cred_filter
 * returns:
 *   PFILTER_REJECT if filter does not apply.
 *   PFILTER_ACCEPT on filter matches.
 *   PFILTER_ERROR on errors.
 */
FUNC_INLINE int
match_cred_uids(__u32 *f, __u32 *index, struct task_struct *task)
{
	__u32 uid;
	int i, ret = PFILTER_REJECT;
	struct cred_filter *cred_f;

	cred_f = (struct cred_filter *)((u64)f + (*index & INDEX_MASK));
	/* 16: type (8 bytes), op (4 bytes), number of values (4 bytes) */
	/* now index points at cred_id of first cred_filter */
	*index += sizeof(struct cred_filter);

	/* error with PFILTER_ERROR */
	if (cred_f->num > MAX_CRED_SELECTOR_VALUES)
		return PFILTER_ERROR;

	if (cred_f->ty == PF_CRED_RUID)
		uid = BPF_CORE_READ(task, cred, uid.val);
	else if (cred_f->ty == PF_CRED_EUID)
		uid = BPF_CORE_READ(task, cred, euid.val);
	else
		return PFILTER_REJECT;

	/* If NotEqual all filter values must return PFILTER_ACCEPT */
	if (cred_f->op == op_filter_neq)
		ret = PFILTER_ACCEPT;

	for (i = 0; i < cred_f->num; i++) {
		if (i > (MAX_CRED_SELECTOR_VALUES - 1)) // pass the verifier
			break;

		if (cred_f->op == op_filter_eq) {
			ret |= __match_cred_uids(f, index, cred_f, uid);
			if (ret == PFILTER_ACCEPT) {
				/* break loop and return */
				/* now index points at the end of cred_filter filter */
				*index += sizeof(struct cred_id) * (cred_f->num - i);
				return ret;
			}
		} else {
			ret &= __match_cred_uids(f, index, cred_f, uid);
			if (ret == PFILTER_REJECT) {
				/* break loop and return */
				/* now index points at the end of cred_filter filter */
				*index += sizeof(struct cred_id) * (cred_f->num - i);
				return ret;
			}
		}
		*index += sizeof(struct cred_id);
		/* now index points at the end of cred_filter filter */
	}

	return ret;
}

/* process_filter_current_cred() match current credentials based on passed filters.
 * returns:
 *   PFILTER_REJECT if filter does not apply.
 *   PFILTER_ACCEPT on filter matches.
 *   PFILTER_ERROR on errors.
 */
FUNC_INLINE int
process_filter_current_cred(__u32 *f, __u32 *index, __u32 len)
{
	__u32 count;
	int i, ret = PFILTER_REJECT;
	struct task_struct *task;

	/* if no current return early */
	task = (struct task_struct *)get_current_task();
	if (unlikely(!task))
		return PFILTER_REJECT;

	/* len must be greater than cred_filter but also at max
	 * equals total of all cred selectors.
	 */
	if (len < sizeof(struct cred_filter) || len > MAX_CRED_SIZE)
		return PFILTER_ERROR;

	count = *(__u32 *)((__u64)f + (*index & INDEX_MASK));
	*index += 4; /* 4: matchCurrentCred count */
	/* Are there any valid credentials filters? */
	if (!count)
		return PFILTER_REJECT;

	/* Here we are at the beginning of matching credentials */

	for (i = 0; i < count; i++) {
		if (i > (MAX_CRED_SELECTOR_FILTERS - 1))
			break;

		ret = match_cred_uids(f, index, task);

		/* If PFILTER_REJECT or PFILTER_ERROR return, otherwise continue */
		if (ret == PFILTER_REJECT || ret == PFILTER_ERROR)
			return ret;
	}

	return ret;
}
#endif

FUNC_INLINE int
process_filter_pid(struct selector_filter *sf, __u32 *f,
		   struct execve_map_value *enter, struct msg_ns *n,
		   struct msg_capabilities *c)
{
	__u32 sel, off = sf->index;
	__u64 flags = sf->flags;
	__u64 pid;

	if (flags & PID_SELECTOR_FLAG_NSPID) {
		pid = enter->nspid;
	} else {
		pid = enter->key.pid;
	}

	if (off > 1000)
		sel = 0;
	else {
		__u64 o = (__u64)off;
		o = o / 4;
		asm volatile("%[o] &= 0x3ff;\n"
			     : [o] "+r"(o));
		sel = f[o];
	}
	return __process_filter_pid(sf->ty, sf->flags, sel, pid, enter);
}

FUNC_INLINE int
process_filter_namespace(struct selector_filter *sf, __u32 *f,
			 struct execve_map_value *enter, struct msg_ns *n,
			 struct msg_capabilities *c)
{
	__u64 nsid = sf->flags;
	__u32 off = sf->index;
	__u32 sel, inum = 0;
	__u64 ty = sf->ty;

	if (off > 1000)
		sel = 0;
	else {
		__u64 o = (__u64)off;
		o = o / 4;
		asm volatile("%[o] &= 0x3ff;\n"
			     : [o] "+r"(o));
		sel = f[o];
	}

	nsid &= 0xf;
	inum = n->inum[nsid];

	/* doing this check before the previous assignment results in for 4.19 kernels:
	 * "math between map_value pointer and register with unbounded min value is not allowed"
	 * where "register with unbounded min value" is nsid. We ensure from the user space
	 * that nsid has a correct value.
	 */
	if (nsid >= ns_max_types)
		return PFILTER_REJECT;

	if (ty == op_filter_in && sel != inum)
		return PFILTER_REJECT;
	else if (ty == op_filter_notin && sel == inum)
		return PFILTER_REJECT;
	return PFILTER_ACCEPT;
}

#ifdef __NS_CHANGES_FILTER
/* If 'ty == op_filter_in' variable 'val' is the mask of the namespaces that we want to check.
 * If 'ty == op_filter_notin' variable 'val' is the mask of the namespaces that we do *NOT* want to check.
 * (namespace bits are defined in the ns_* enum in process.h)
 */
FUNC_INLINE int
process_filter_namespace_change(__u64 ty, __u64 val,
				struct execve_map_value *enter,
				struct msg_ns *n, struct msg_capabilities *c,
				struct msg_selector_data *sel)
{
	struct execve_map_value *init;
	__u32 pid;
	__u64 i;

	pid = (get_current_pid_tgid() >> 32);
	init = execve_map_get_noinit(pid); // reject for processes that are not in the execve_map yet
	if (!init)
		return PFILTER_REJECT;

	if (ty == op_filter_in) { // For the op_filter_in
		for (i = 0; i < ns_max_types; i++) { // ... check all possible namespaces
			if (val & (1 << i)) { // ... if the appropriate bit is set (bit positions defined in ns_* enum)
				if (init->ns.inum[i] == 0) { // namespace not set so just ignore
					sel->match_ns = 1; // ... but need to setup the correct values at the end
					continue;
				}
				if (init->ns.inum[i] != n->inum[i]) { // does the namespace value changed?
					sel->match_ns = 1;
					return PFILTER_ACCEPT;
				}
			}
		}
	} else if (ty == op_filter_notin) { // For the op_filter_notin
		for (i = 0; i < ns_max_types;
		     i++) { // ... check all possible namespaces
			if ((val & (1 << i)) == 0) { // ... if the appropriate bit is *NOT* set (bit positions defined in ns_* enum)
				if (init->ns.inum[i] == 0) { // namespace not set so just ignore
					sel->match_ns = 1; // ... but need to setup the correct values at the end
					continue;
				}
				if (init->ns.inum[i] != n->inum[i]) { // does the namespace value changed?
					sel->match_ns = 1;
					return PFILTER_ACCEPT;
				}
			}
		}
	}

	return PFILTER_REJECT;
}
#endif

FUNC_INLINE int
process_filter_capabilities(__u32 ty, __u32 op, __u32 ns, __u64 val,
			    struct msg_ns *n, struct msg_capabilities *c)
{
	__u64 caps;

	/* if ns != 0 we care only for events in different than the host user namespace */
	if (ns != 0 && n->user_inum == ns)
		return PFILTER_REJECT;

	/* We should not reach that. Userspace checks that. */
	if (ty > caps_inheritable)
		return PFILTER_REJECT;

	caps = c->c[ty];

	if (op == op_filter_in)
		return (caps & val) ? PFILTER_ACCEPT : PFILTER_REJECT;
	/* op_filter_notin */
	return (caps & val) ? PFILTER_REJECT : PFILTER_ACCEPT;
}

#ifdef __CAP_CHANGES_FILTER
FUNC_INLINE int
process_filter_capability_change(__u32 ty, __u32 op, __u32 ns, __u64 val,
				 struct msg_ns *n, struct msg_capabilities *c,
				 struct msg_selector_data *sel)
{
	struct execve_map_value *init;
	bool match = false;
	__u64 icaps, ccaps;
	__u32 pid;

	pid = (get_current_pid_tgid() >> 32);
	init = execve_map_get_noinit(
		pid); /* reject for processes that are not in the execve_map yet */
	if (!init)
		return PFILTER_REJECT;

	/* if ns != 0 we care only for events in different than the host user namespace */
	if (ns != 0 && n->user_inum == ns)
		return PFILTER_REJECT;

	if (ty >
	    caps_inheritable) /* We should not reach that. Userspace checks that. */
		return PFILTER_REJECT;

	icaps = init->caps.c[ty];

	// When compiling bpf_generic_kprobe_v53.o with clang-18 and loading it on
	// 5.4.278, the verifier complains than ty could be negative while in this
	// context it's just the capability set type (effective, inheritable, or
	// permitted), let's blindly remind the verifier it's a u32.
	asm volatile("%[ty] &= 0xffffffff;\n"
		     : [ty] "+r"(ty));
	ccaps = c->c[ty];

	/* we have a change in the capabilities that we care */
	if ((icaps & val) != (ccaps & val))
		match = (op == op_filter_in);
	else if (icaps != ccaps) /* we have a change in other capabilities */
		match = (op == op_filter_notin);

	if (match) {
		/* this will update our internal metadata of the processe's caps */
		sel->match_cap = 1;
	}
	return match ? PFILTER_ACCEPT : PFILTER_REJECT;
}
#endif

#define MAX_SELECTOR_VALUES 4

FUNC_INLINE int
selector_match(__u32 *f, struct selector_filter *sel,
	       struct execve_map_value *enter,
	       struct msg_generic_kprobe *msg,
	       int (*process_filter)(struct selector_filter *, __u32 *,
				     struct execve_map_value *, struct msg_ns *,
				     struct msg_capabilities *))
{
	int res[MAX_SELECTOR_VALUES] = { 0 };
	__u32 index = sel->index;
	__u64 len = sel->len;
	__u64 ty = sel->ty;
	__u64 i;

	if (len > MAX_SELECTOR_VALUES)
		len = MAX_SELECTOR_VALUES;

	/* For NotIn op we AND results so default to 1 so we fallthru open */
	if (ty == op_filter_notin) {
#pragma unroll
		for (i = 0; i < MAX_SELECTOR_VALUES; i++)
			res[i] = 1;
	}

	/* Updating the number of iterations below, you should also
	 * update the function namespaceSelectorValue() in kernel.go
	 */
#ifdef __LARGE_BPF_PROG
	for (i = 0; i < len; i++) {
		if (i > (MAX_SELECTOR_VALUES - 1)) // we need to make the verifier happy
			break;
		res[i] = process_filter(sel, f, enter, &msg->ns, &msg->caps);
		index = next_pid_value(index, f, ty);
		sel->index = index;
	}
#else
	/* Unrolling this loop was problematic for clang so rather
	 * than fight with clang just open code it. Its hard to see
	 * how many pid values will be used anyways. Having zero
	 * length values is an input error that CRD should catch.
	 */
	if (len == 4)
		goto four;
	else if (len == 3)
		goto three;
	else if (len == 2)
		goto two;
	else if (len == 1)
		goto one;
four:
	res[3] = process_filter(sel, f, enter, &msg->ns, &msg->caps);
	index = next_pid_value(index, f, ty);
	sel->index = index;
three:
	res[2] = process_filter(sel, f, enter, &msg->ns, &msg->caps);
	index = next_pid_value(index, f, ty);
	sel->index = index;
two:
	res[1] = process_filter(sel, f, enter, &msg->ns, &msg->caps);
	index = next_pid_value(index, f, ty);
	sel->index = index;
one:
	res[0] = process_filter(sel, f, enter, &msg->ns, &msg->caps);
	index = next_pid_value(index, f, ty);
	sel->index = index;
#endif

	if (ty == op_filter_notin)
		return res[0] & res[1] & res[2] & res[3];
	else
		return res[0] | res[1] | res[2] | res[3];
}

struct pid_filter {
	u32 op; /* op (i.e. op_filter_in or op_filter_notin) */
	u32 flags; /* PID_SELECTOR_FLAG_NSPID or PID_SELECTOR_FLAG_FOLLOW */
	u32 len; /* number of values */
	u32 val[]; /* values */
} __attribute__((packed));

struct ns_filter {
	u32 ty; /* namespace (i.e. ns_uts, ns_net, ns_pid, ...) */
	u32 op; /* op (i.e. op_filter_in or op_filter_notin) */
	u32 len; /* number of values */
	u32 val[]; /* values */
} __attribute__((packed));

struct caps_filter {
	u32 ty; /* (i.e. effective, inheritable, or permitted) */
	u32 op; /* op (i.e. op_filter_in or op_filter_notin) */
	u32 ns; /* If ns == 0 <=> IsNamespaceCapability == false. Otheriwse it contains the value of host user namespace. */
	u64 val; /* OR-ed capability values */
} __attribute__((packed));

struct nc_filter {
	u32 op; /* op (i.e. op_filter_in or op_filter_notin) */
	u32 value; /* contains all namespaces to monitor (i.e. bit 0 is for ns_uts, bit 1 for ns_ipc etc.) */
} __attribute__((packed));

#define VALUES_MASK 0x1f /* max 4 values with 4 bytes each | 0x1f == 31 */

/* If you update the value of NUM_NS_FILTERS_SMALL below you should
 * also update parseMatchNamespaces() in kernel.go
 */
#define NUM_NS_FILTERS_SMALL 4

FUNC_INLINE int
selector_process_filter(__u32 *f, __u32 index, struct execve_map_value *enter,
			struct msg_generic_kprobe *msg)
{
	int res = PFILTER_ACCEPT;
	struct pid_filter *pid;
	struct ns_filter *ns;
#ifdef __NS_CHANGES_FILTER
	struct nc_filter *nc;
#endif
	struct caps_filter *caps;
	__u32 len;
	__u64 i;

	/* Do binary filter first for selector index */
	if (!match_binaries(index, enter))
		return 0;

	/* Find selector offset byte index */
	index *= 4;
	index += 4;

	/* read the start offset of the corresponding selector */
	/* selector section offset by reading the relative offset in the array */
	i = index;
	asm volatile("%[i] &= 0x3ff;\n" // INDEX_MASK
		     : [i] "+r"(i));
	index += *(__u32 *)((__u64)f + i);
	index &= INDEX_MASK;
	index += 4; /* skip selector size field */

	/* matchPid */
	/* (sizeof(pid1) + sizeof(pid2) + ... + 4) */
	len = *(__u32 *)((__u64)f + (index & INDEX_MASK));
	index += 4; /* 4: pid header */

	/* we can have only matchNamespace */
	if (len > 4) {
		pid = (struct pid_filter *)((u64)f + index);
		/* 12: op, flags, length */
		index += sizeof(struct pid_filter);
		struct selector_filter sel = {
			.index = index,
			.ty = pid->op,
			.flags = pid->flags,
			.len = pid->len,
		};
		res = selector_match(f, &sel, enter, msg, &process_filter_pid);
		/* now index points at the end of PID filter */
		index += ((pid->len * sizeof(pid->val[0])) & VALUES_MASK);
	}
	if (res == PFILTER_REJECT)
		return res;

	/* matchNamespace */
	/* (sizeof(ns1) + sizeof(ns2) + ... + 4) */
	len = *(__u32 *)((__u64)f + (index & INDEX_MASK));
	index += 4; /* 4: ns header */
	len -= 4;

#ifdef __LARGE_BPF_PROG
	for (i = 0; i < ns_max_types; i++) {
#else
#pragma unroll
	/* with more than 4 iterations it results in too big programs */
	for (i = 0; i < NUM_NS_FILTERS_SMALL; i++) {
#endif
		if (len > 0) {
			ns = (struct ns_filter *)((u64)f + (index & INDEX_MASK));
			/* 12: namespace, op, length */
			index += sizeof(struct ns_filter);
			struct selector_filter sel = {
				.index = index,
				.ty = ns->op,
				.flags = ns->ty,
				.len = ns->len,
			};
			res = selector_match(f, &sel, enter, msg,
					     &process_filter_namespace);
			/* now index points at the end of namespace filter */
			index += ((ns->len * sizeof(ns->val[0])) & VALUES_MASK);
			len -= (sizeof(struct ns_filter) + (ns->len * sizeof(ns->val[0])));
		}
		if (res == PFILTER_REJECT)
			return res;
	}

	/* matchCapabilities */
	/* (sizeof(cap1) + sizeof(cap2) + ... + 4) */
	len = *(__u32 *)((__u64)f + (index & INDEX_MASK));
	index += 4; /* 4: caps header */
	len -= 4;

	if (len > 0) {
		caps = (struct caps_filter *)((u64)f + (index & INDEX_MASK));
		index += sizeof(struct caps_filter); /* 20: ty, op, ns, val */
		res = process_filter_capabilities(caps->ty, caps->op, caps->ns,
						  caps->val, &msg->ns, &msg->caps);
	}
	if (res == PFILTER_REJECT)
		return res;

	/* matchCurrentCred
	 *
	 * Depends on LARGE_BPF_PROG to be available, if not then userspace writes
	 * 4 bytes size length and advances the offset index with same 4 bytes.
	 *
	 * (4 (length) + 4 (counter) + sizeof(ruid) + sizeof(rgid) + ...
	 */
	len = *(__u32 *)((__u64)f + (index & INDEX_MASK));
	index += 4; /* 4: matchCurrentCred header */
	len -= 4;

#ifdef __LARGE_BPF_PROG
	/* Filter current task credentials */
	if (len > 0)
		res = process_filter_current_cred(f, &index, len);

	if (res == PFILTER_REJECT)
		return res;
#endif

#ifdef __NS_CHANGES_FILTER
	/* matchNamespaceChanges */
	/* (sizeof(nc1) + sizeof(nc2) + ... + 4) */
	len = *(__u32 *)((__u64)f + (index & INDEX_MASK));
	index += 4; /* 4: nc header */
	len -= 4;

	if (len > 0) {
		nc = (struct nc_filter *)((u64)f + (index & INDEX_MASK));
		index += sizeof(struct nc_filter); /* 8: op, val */
		res = process_filter_namespace_change(nc->op, nc->value, enter,
						      &msg->ns, &msg->caps, &msg->sel);
		/* now index points at the end of namespace change filter */
	}
	if (res == PFILTER_REJECT)
		return res;
#endif

#ifdef __CAP_CHANGES_FILTER
	/* matchCapabilityChanges */
	len = *(__u32 *)((__u64)f +
			 (index &
			  INDEX_MASK)); /* (sizeof(cap1) + sizeof(cap2) + ... + 4) */
	index += 4; /* 4: caps header */
	len -= 4;

	if (len > 0) {
		caps = (struct caps_filter *)((u64)f + (index & INDEX_MASK));
		index += sizeof(struct caps_filter); /* 20: ty, op, ns, val */
		res = process_filter_capability_change(
			caps->ty, caps->op, caps->ns, caps->val, &msg->ns, &msg->caps, &msg->sel);
	}
	if (res == PFILTER_REJECT)
		return res;
#endif

	return res;
}

FUNC_INLINE int
process_filter_done(struct msg_selector_data *sel,
		    struct execve_map_value *enter,
		    struct msg_execve_key *current)
{
	current->pid = enter->key.pid;
	current->ktime = enter->key.ktime;
	if (sel->pass)
		return PFILTER_ACCEPT;
	return PFILTER_REJECT;
}
#endif /* __PFILTER_H__ */
