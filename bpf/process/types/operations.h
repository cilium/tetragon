// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __OPERATIONS_H__
#define __OPERATIONS_H__

enum {
	op_filter_none = 0,
	op_filter_gt = 1,
	op_filter_lt = 2,
	op_filter_eq = 3,
	op_filter_neq = 4,
	// pid and namespace ops
	op_filter_in = 5,
	op_filter_notin = 6,
	// string ops
	op_filter_str_contains = 7,
	op_filter_str_prefix = 8,
	op_filter_str_postfix = 9,
	// map membership ops
	op_filter_inmap = 10,
	op_filter_notinmap = 11,
	op_filter_mask = 12,
	// socket ops
	op_filter_saddr = 13,
	op_filter_daddr = 14,
	op_filter_sport = 15,
	op_filter_dport = 16,
	op_filter_protocol = 17,
	op_filter_notsport = 18,
	op_filter_notdport = 19,
	op_filter_sportpriv = 20,
	op_filter_notsportpriv = 21,
	op_filter_dportpriv = 22,
	op_filter_notdportpriv = 23,
	op_filter_notsaddr = 24,
	op_filter_notdaddr = 25,
	// file ops
	op_filter_str_notprefix = 26,
	op_filter_str_notpostfix = 27,
	// more socket ops
	op_filter_family = 28,
	op_filter_state = 29,
	// capability ops
	op_capabilities_gained = 30,
	// range
	op_in_range = 31,
	op_notin_range = 32,
	// match substring
	op_substring = 33,
	op_substring_igncase = 34,
	// file type
	op_filter_file_type = 35,
	op_filter_not_file_type = 36,
};

#endif // __OPERATIONS_H__
