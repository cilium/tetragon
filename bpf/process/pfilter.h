
/**
 * Process filters
 * see generic_process_filter below
 */

#define FIND_PIDSET(value, isns)                                               \
	{                                                                      \
		if (!filter)                                                   \
			return 0;                                              \
		{                                                              \
			__u32 pid, ppid = 0;                                   \
			if (isns) {                                            \
				pid = filter->nspid;                           \
			} else {                                               \
				pid = filter->key.pid;                         \
				ppid = filter->pkey.pid;                       \
			}                                                      \
			if (pid == value || ppid == value) {                   \
				pidset_found = true;                           \
				goto accept;                                   \
			}                                                      \
		}                                                              \
		filter = map_lookup_elem(&execve_map, &filter->pkey.pid);      \
	}

#define FIND_PIDSET10(VAL, ISNS)                                               \
	{                                                                      \
		FIND_PIDSET(VAL, ISNS)                                         \
		FIND_PIDSET(VAL, ISNS)                                         \
		FIND_PIDSET(VAL, ISNS)                                         \
		FIND_PIDSET(VAL, ISNS)                                         \
		FIND_PIDSET(VAL, ISNS)                                         \
		FIND_PIDSET(VAL, ISNS)                                         \
		FIND_PIDSET(VAL, ISNS)                                         \
		FIND_PIDSET(VAL, ISNS)                                         \
		FIND_PIDSET(VAL, ISNS)                                         \
	}

#define FILTER_PIDSET(VAL)                                                     \
	{                                                                      \
		FIND_PIDSET10(VAL)                                             \
	}

static inline __attribute__((always_inline)) bool
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

static inline __attribute__((always_inline)) bool
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

static inline __attribute__((always_inline)) int
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

static inline __attribute__((always_inline)) int
next_pid_value(__u32 off, __u32 *f, __u32 ty)
{
	return off + 4;
}

static inline __attribute__((always_inline)) int
process_filter_pid(__u32 i, __u32 off, __u32 *f, __u64 ty, __u64 flags,
		   struct execve_map_value *enter, void *heap)
{
	__u32 sel;
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
		asm volatile("%[o] &= 0x3ff;\n" ::[o] "+r"(o) :);
		sel = f[o];
	}
	return __process_filter_pid(ty, flags, sel, pid, enter);
}

static inline __attribute__((always_inline)) int
process_filter_namespace(__u32 i, __u32 off, __u32 *f, __u64 ty, __u64 nsid,
			 struct execve_map_value *enter, void *heap)
{
	__u32 sel, inum = 0;
	struct msg_generic_kprobe *msg;
	int zero = 0;

	if (off > 1000)
		sel = 0;
	else {
		__u64 o = (__u64)off;
		o = o / 4;
		asm volatile("%[o] &= 0x3ff;\n" ::[o] "+r"(o) :);
		sel = f[o];
	}

	msg = map_lookup_elem(heap, &zero);
	if (!msg)
		return PFILTER_REJECT;

	nsid &= 0xf;
	inum = msg->ns.inum[nsid];

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
 * (namespace bits are defined in the ns_* enum in hubble_msg.h)
 */
static inline __attribute__((always_inline)) int
process_filter_namespace_change(__u64 ty, __u64 val,
				struct execve_map_value *enter, void *heap)
{
	struct execve_map_value *init;
	struct msg_generic_kprobe *curr;
	__u32 pid;
	__u64 n;
	int zero = 0;

	curr = map_lookup_elem(heap, &zero);
	if (!curr)
		return PFILTER_REJECT;

	pid = (get_current_pid_tgid() >> 32);
	init = execve_map_get_noinit(
		pid); // reject for processes that are not in the execve_map yet
	if (!init)
		return PFILTER_REJECT;

	if (ty == op_filter_in) { // For the op_filter_in
		for (n = 0; n < ns_max_types;
		     n++) { // ... check all possible namespaces
			if (val &
			    (1
			     << n)) { // ... if the appropriate bit is set (bit positions defined in ns_* enum)
				if (init->ns.inum[n] ==
				    0) { // namespace not set so just ignore
					curr->match_ns =
						1; // ... but need to setup the correct values at the end
					continue;
				}
				if (init->ns.inum[n] !=
				    curr->ns.inum[n]) { // does the namespace value changed?
					curr->match_ns = 1;
					return PFILTER_ACCEPT;
				}
			}
		}
	} else if (ty == op_filter_notin) { // For the op_filter_notin
		for (n = 0; n < ns_max_types;
		     n++) { // ... check all possible namespaces
			if ((val & (1 << n)) ==
			    0) { // ... if the appropriate bit is *NOT* set (bit positions defined in ns_* enum)
				if (init->ns.inum[n] ==
				    0) { // namespace not set so just ignore
					curr->match_ns =
						1; // ... but need to setup the correct values at the end
					continue;
				}
				if (init->ns.inum[n] !=
				    curr->ns.inum[n]) { // does the namespace value changed?
					curr->match_ns = 1;
					return PFILTER_ACCEPT;
				}
			}
		}
	}

	return PFILTER_REJECT;
}
#endif

static inline __attribute__((always_inline)) int
process_filter_capabilities(__u32 ty, __u32 op, __u32 ns, __u64 val, void *heap)
{
	struct msg_generic_kprobe *msg;
	int zero = 0;
	__u64 caps;

	msg = map_lookup_elem(heap, &zero);
	if (!msg)
		return PFILTER_REJECT;

	/* if ns != 0 we care only for events in different than the host user namespace */
	if ((ns != 0) && (msg->ns.user_inum == ns))
		return PFILTER_REJECT;

	if (ty >
	    caps_inheritable) /* We should not reach that. Userspace checks that. */
		return PFILTER_REJECT;

	caps = msg->caps.c[ty];

	if (op == op_filter_in)
		return (caps & val) ? PFILTER_ACCEPT : PFILTER_REJECT;
	return (caps & val) ? PFILTER_REJECT :
			      PFILTER_ACCEPT; /* op_filter_notin */
}

#ifdef __CAP_CHANGES_FILTER
static inline __attribute__((always_inline)) int
process_filter_capability_change(__u32 ty, __u32 op, __u32 ns, __u64 val,
				 void *heap)
{
	struct execve_map_value *init;
	struct msg_generic_kprobe *curr;
	int zero = 0;
	bool match = false;
	__u64 icaps, ccaps;
	__u32 pid;

	curr = map_lookup_elem(heap, &zero);
	if (!curr)
		return PFILTER_REJECT;

	pid = (get_current_pid_tgid() >> 32);
	init = execve_map_get_noinit(
		pid); /* reject for processes that are not in the execve_map yet */
	if (!init)
		return PFILTER_REJECT;

	/* if ns != 0 we care only for events in different than the host user namespace */
	if ((ns != 0) && (curr->ns.user_inum == ns))
		return PFILTER_REJECT;

	if (ty >
	    caps_inheritable) /* We should not reach that. Userspace checks that. */
		return PFILTER_REJECT;

	icaps = init->caps.c[ty];
	ccaps = curr->caps.c[ty];

	/* we have a change in the capabilities that we care */
	if ((icaps & val) != (ccaps & val))
		match = (op == op_filter_in);
	else if (icaps != ccaps) /* we have a change in other capabilities */
		match = (op == op_filter_notin);

	if (match) {
		/* this will update our internal metadata of the processe's caps */
		curr->match_cap = 1;
	}
	return match ? PFILTER_ACCEPT : PFILTER_REJECT;
}
#endif

#define MAX_SELECTOR_VALUES 4

static inline __attribute__((always_inline)) int
selector_match(__u32 *f, __u32 index, __u64 ty, __u64 flags, __u64 len,
	       struct execve_map_value *enter, void *heap,
	       int (*process_filter)(__u32, __u32, __u32 *, __u64, __u64,
				     struct execve_map_value *, void *))
{
	int res1 = 0, res2 = 0, res3 = 0, res4 = 0;

	/* For NotIn op we AND results so default to 1 so we fallthru open */
	if (ty == op_filter_notin)
		res1 = res2 = res3 = res4 = 1;

	/* Unrolling this loop was problematic for clang so rather
	 * than fight with clang just open code it. Its hard to see
	 * how many pid values will be used anyways. Having zero
	 * length values is an input error that CRD should catch.
	 */
	/* Updateing the number of iterations below, you should also
	 * update the function namespaceSelectorValue() in kernel.go
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
	res4 = process_filter(3, index, f, ty, flags, enter, heap);
	index = next_pid_value(index, f, ty);
three:
	res3 = process_filter(2, index, f, ty, flags, enter, heap);
	index = next_pid_value(index, f, ty);
two:
	res2 = process_filter(1, index, f, ty, flags, enter, heap);
	index = next_pid_value(index, f, ty);
one:
	res1 = process_filter(0, index, f, ty, flags, enter, heap);
	index = next_pid_value(index, f, ty);

	if (ty == op_filter_notin)
		return res1 & res2 & res3 & res4;
	else
		return res1 | res2 | res3 | res4;
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

static inline __attribute__((always_inline)) int
selector_process_filter(__u32 *f, __u32 index, struct execve_map_value *enter,
			void *heap)
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

	/* Find selector offset byte index */
	index *= 4;
	index += 4;

	/* read the start offset of the corresponding selector */
	index = *(__u32 *)((__u64)f + (index & INDEX_MASK));

	index &= INDEX_MASK;
	index += 8; /* 8: selector value and selector header */

	/* matchPid */
	len = *(__u32 *)((__u64)f +
			 (index &
			  INDEX_MASK)); /* (sizeof(pid1) + sizeof(pid2) + ... + 4) */
	index += 4; /* 4: pid header */

	if (len > 4) { /* we can have only matchNamespace */
		pid = (struct pid_filter *)((u64)f + index);
		index += sizeof(struct pid_filter); /* 12: op, flags, length */
		res = selector_match(f, index, pid->op, pid->flags, pid->len,
				     enter, heap, &process_filter_pid);
		index +=
			((pid->len * sizeof(pid->val[0])) &
			 VALUES_MASK); /* now index points at the end of PID filter */
	}
	if (res == PFILTER_REJECT)
		return res;

	/* matchNamespace */
	len = *(__u32 *)((__u64)f +
			 (index &
			  INDEX_MASK)); /* (sizeof(ns1) + sizeof(ns2) + ... + 4) */
	index += 4; /* 4: ns header */
	len -= 4;

#ifdef __LARGE_BPF_PROG
	for (i = 0; i < ns_max_types; i++) {
#else
#pragma unroll
	for (i = 0; i < NUM_NS_FILTERS_SMALL;
	     i++) { /* with more than 4 iterations it results in too big programs */
#endif
		if (len > 0) {
			ns = (struct ns_filter *)((u64)f +
						  (index & INDEX_MASK));
			index += sizeof(
				struct ns_filter); /* 12: namespace, op, length */
			res = selector_match(f, index, ns->op, ns->ty, ns->len,
					     enter, heap,
					     &process_filter_namespace);
			index +=
				((ns->len * sizeof(ns->val[0])) &
				 VALUES_MASK); /* now index points at the end of namespace filter */
			len -= (sizeof(struct ns_filter) +
				(ns->len * sizeof(ns->val[0])));
		}
		if (res == PFILTER_REJECT)
			return res;
	}

	/* matchCapabilities */
	len = *(__u32 *)((__u64)f +
			 (index &
			  INDEX_MASK)); /* (sizeof(cap1) + sizeof(cap2) + ... + 4) */
	index += 4; /* 4: caps header */
	len -= 4;

	if (len > 0) {
		caps = (struct caps_filter *)((u64)f + (index & INDEX_MASK));
		index += sizeof(struct caps_filter); /* 20: ty, op, ns, val */
		res = process_filter_capabilities(caps->ty, caps->op, caps->ns,
						  caps->val, heap);
	}
	if (res == PFILTER_REJECT)
		return res;

#ifdef __NS_CHANGES_FILTER
	/* matchNamespaceChanges */
	len = *(__u32 *)((__u64)f +
			 (index &
			  INDEX_MASK)); /* (sizeof(nc1) + sizeof(nc2) + ... + 4) */
	index += 4; /* 4: nc header */
	len -= 4;

	if (len > 0) {
		nc = (struct nc_filter *)((u64)f + (index & INDEX_MASK));
		index += sizeof(struct nc_filter); /* 8: op, val */
		res = process_filter_namespace_change(nc->op, nc->value, enter,
						      heap);
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
			caps->ty, caps->op, caps->ns, caps->val, heap);
	}
	if (res == PFILTER_REJECT)
		return res;
#endif

	return res;
}

#define MAX_SELECTORS 8

static inline __attribute__((always_inline)) int
process_filter_done(struct msg_generic_kprobe *msg,
		    struct execve_map_value *enter,
		    struct msg_execve_key *current)
{
	current->pid = enter->key.pid;
	current->ktime = enter->key.ktime;
	if (msg->pass) {
		return PFILTER_ACCEPT;
	}
	return PFILTER_REJECT;
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
static inline __attribute__((always_inline)) int
generic_process_filter(struct msg_generic_kprobe *msg, void *fmap, void *heap)
{
	struct msg_execve_key *current = &msg->current;
	struct execve_map_value *enter;
	bool walker = 0;
	__u32 ppid;
	int curr;

	enter = event_find_curr(&ppid, 0, &walker);
	if (enter) {
		int zero = 0, selectors, pass;
		__u32 *f = map_lookup_elem(fmap, &zero);

		if (!f)
			return PFILTER_ERROR;

		curr = msg->curr;
		if (curr > MAX_SELECTORS)
			return process_filter_done(msg, enter, current);

		selectors = f[0];
		/* If no selectors accept process */
		if (!selectors) {
			msg->pass = true;
			return process_filter_done(msg, enter, current);
		}

		/* If we get here with reference to uninitialized selector drop */
		if (selectors <= curr)
			return process_filter_done(msg, enter, current);

		pass = selector_process_filter(
			f, curr, enter,
			heap); /* matches the PID and Namespace */
		if (pass) {
			/* Verify lost that msg is not null here so recheck */
			asm volatile("%[curr] &= 0x1f;\n" ::[curr] "r+"(curr)
				     :);
			msg->active[curr] = true;
			msg->active[SELECTORS_ACTIVE] = true;
			msg->pass |= true;
		}
		msg->curr++;
		if (msg->curr > selectors)
			return process_filter_done(msg, enter, current);
		return PFILTER_CONTINUE; /* will iterate to the next selector */
	}
	return PFILTER_CURR_NOT_FOUND;
}
