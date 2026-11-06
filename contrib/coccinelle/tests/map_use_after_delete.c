// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Copyright Authors of Tetragon

// Test cases for map_use_after_delete.cocci, see check.sh: the uses on the
// lines with a REPORT comment must be reported, and nothing else.

// Reported: the value is used after deleting its entry.

int same_key(void)
{
	struct value *v;

	v = map_lookup_elem(&m, &k1);
	if (!v)
		return 0;
	map_delete_elem(&m, &k1);
	return v->x; // REPORT
}

int same_key_errmetrics(void)
{
	struct value *v;

	v = with_errmetrics_ptr(map_lookup_elem, &m, &k1);
	if (!v)
		return 0;
	with_errmetrics(map_delete_elem, &m, &k1);
	return v->x; // REPORT
}

int same_key_passed_on(void)
{
	struct value *v;

	v = map_lookup_elem(&m, &k1);
	if (!v)
		return 0;
	map_delete_elem(&m, &k1);
	send_event(ctx, v); // REPORT
	return 0;
}

int same_key_in_branch(void)
{
	struct value *v;

	v = map_lookup_elem(&m, &k1);
	if (v)
		map_delete_elem(&m, &k1);
	if (!v)
		return 0;
	return v->x; // REPORT
}

int execve_map_wrappers(__u32 pid)
{
	struct execve_map_value *e;

	e = execve_map_get_noinit(pid);
	if (!e)
		return 0;
	execve_map_delete(pid);
	return e->x; // REPORT
}

int execve_map_lookup_and_wrapper(__u32 pid)
{
	struct execve_map_value *e;

	e = map_lookup_elem(&execve_map, &pid);
	if (!e)
		return 0;
	execve_map_delete(pid);
	return e->x; // REPORT
}

// matched by both rules, but reported once
int execve_map_direct(__u32 pid)
{
	struct execve_map_value *e;

	e = map_lookup_elem(&execve_map, &pid);
	if (!e)
		return 0;
	map_delete_elem(&execve_map, &pid);
	return e->x; // REPORT
}

// whether the keys are the same can't always be told from the code, so a
// delete with a different key is reported too
int different_keys(void)
{
	struct value *v;

	v = map_lookup_elem(&m, &k1);
	if (!v)
		return 0;
	map_delete_elem(&m, &k2);
	return v->x; // REPORT
}

int different_keys_errmetrics(void)
{
	struct value *v;

	v = with_errmetrics_ptr(map_lookup_elem, &m, &k1);
	if (!v)
		return 0;
	with_errmetrics(map_delete_elem, &m, &k2);
	return v->x; // REPORT
}

int execve_map_different_keys(__u32 pid, __u32 other)
{
	struct execve_map_value *e;

	e = execve_map_get_noinit(pid);
	if (!e)
		return 0;
	execve_map_delete(other);
	return e->x; // REPORT
}

// Not reported.

int different_maps(void)
{
	struct value *v;

	v = map_lookup_elem(&m1, &k1);
	if (!v)
		return 0;
	map_delete_elem(&m2, &k1);
	return v->x;
}

int used_before_delete(void)
{
	struct value *v;
	int x;

	v = map_lookup_elem(&m, &k1);
	if (!v)
		return 0;
	x = v->x;
	map_delete_elem(&m, &k1);
	return x;
}

int tested_after_delete(void)
{
	struct value *v;

	v = map_lookup_elem(&m, &k1);
	map_delete_elem(&m, &k1);
	if (!v)
		return 0;
	return v != NULL;
}

int reassigned_after_delete(void)
{
	struct value *v;

	v = map_lookup_elem(&m, &k1);
	if (!v)
		return 0;
	map_delete_elem(&m, &k1);
	v = map_lookup_elem(&m, &k2);
	if (!v)
		return 0;
	return v->x;
}
