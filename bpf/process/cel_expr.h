// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __CEL_EXPR_H__
#define __CEL_EXPR_H__

/*
 * The code for the cel_expr_N functions will be generated and linked when the policy is loaded
 */

#if defined(GENERIC_KPROBE) && !defined(__MULTI_KPROBE)
int cel_expr_0(long *argsoff, char *args);
int cel_expr_1(long *argsoff, char *args);
int cel_expr_2(long *argsoff, char *args);
int cel_expr_3(long *argsoff, char *args);
int cel_expr_4(long *argsoff, char *args);
int cel_expr_5(long *argsoff, char *args);
int cel_expr_6(long *argsoff, char *args);
int cel_expr_7(long *argsoff, char *args);

FUNC_LOCAL int
cel_expr(int id, long *argsoff, char *args)
{
	switch (id) {
	case 0:
		return cel_expr_0(argsoff, args);
	case 1:
		return cel_expr_1(argsoff, args);
	case 2:
		return cel_expr_2(argsoff, args);
	case 3:
		return cel_expr_3(argsoff, args);
	case 4:
		return cel_expr_4(argsoff, args);
	case 5:
		return cel_expr_5(argsoff, args);
	case 6:
		return cel_expr_6(argsoff, args);
	case 7:
		return cel_expr_7(argsoff, args);
	/* should not happen  */
	default:
		return 0;
	}
}
#else
FUNC_LOCAL int
cel_expr(int id, long *argsoff, char *args)
{
	return 0;
}
#endif /* GENERIC_KPROBE && !__MULTI_KPROBE */

#endif /* __CEL_EXPR_H__ */
