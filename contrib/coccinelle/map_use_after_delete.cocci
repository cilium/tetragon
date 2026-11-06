// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Copyright Authors of Tetragon
//
// Find map values used after deleting their map entry.
//
// Running under RCU only makes this memory safe: on delete, the element is
// given back to the map freelist (or to bpf_mem_alloc) without waiting for a
// grace period, so it can be reused and overwritten by another update while it
// is still being read. Use, or copy, the needed data before deleting the entry.
//
// A delete of the same map is reported whatever its key: whether the keys are
// the same often can't be told from the code, e.g. different expressions with
// the same value, so a delete with a different key is reported too. Testing the
// pointer against NULL, comparing it, or assigning it after the delete is fine:
// only reading through it, or passing it on, is reported.

virtual report

@initialize:python@
@@
# a lookup and delete of execve_map can match both rules below
reported = set()

def report_use(p, pd, pu):
    key = (pu[0].file, pu[0].line, pu[0].column)
    if key not in reported:
        reported.add(key)
        coccilib.report.print_report(pu[0],
            "%s used after deleting its map entry on line %s" % (p, pd[0].line))

// Uses of a pointer that don't read the element it points to.
@cmp@
identifier p;
expression E;
position pos;
@@
(
 p@pos = E
|
 !p@pos
|
 p@pos == E
|
 p@pos != E
|
 E == p@pos
|
 E != p@pos
)

@cmp_if@
identifier p;
statement S1, S2;
position pos;
@@
(
 if (p@pos) S1 else S2
|
 if (p@pos) S1
)

// Lookup and delete of the same map.
@r exists@
symbol map_lookup_elem, map_delete_elem;
expression M, K1, K2, E;
identifier p;
position pd, pu != {cmp.pos, cmp_if.pos};
@@
(
 p = map_lookup_elem(M, K1)
|
 p = with_errmetrics_ptr(map_lookup_elem, M, K1)
)
... when != p = E
(
 map_delete_elem@pd(M, K2)
|
 with_errmetrics@pd(map_delete_elem, M, K2)
)
... when != p = E
 p@pu

// execve_map wrappers, which hide the map.
@r_execve exists@
symbol execve_map;
expression K1, K2, E;
identifier p;
position pd, pu != {cmp.pos, cmp_if.pos};
@@
(
 p = execve_map_get(K1)
|
 p = execve_map_get_noinit(K1)
|
 p = map_lookup_elem(&execve_map, K1)
)
... when != p = E
(
 execve_map_delete@pd(K2)
|
 map_delete_elem@pd(&execve_map, K2)
)
... when != p = E
 p@pu

@script:python depends on report@
p << r.p;
pd << r.pd;
pu << r.pu;
@@
report_use(p, pd, pu)

@script:python depends on report@
p << r_execve.p;
pd << r_execve.pd;
pu << r_execve.pu;
@@
report_use(p, pd, pu)
