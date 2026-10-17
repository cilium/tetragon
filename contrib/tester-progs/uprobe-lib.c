#include <stdio.h>

int uprobe_test_lib_pizza(int c)
{
    printf("uprobe_test_lib_pizza called\n");
    return c + 1;
}

// Override replacement for fp_args() in uprobe-fp-args.c.
// Returns a bitmask of the arguments not matching the values passed by the caller.
int uprobe_test_lib_fp_args(double a0, double a1, double a2, double a3,
			    double a4, double a5, double a6, double a7)
{
	const double expected[8] = { 1.5, 2.5, 3.5, 4.5, 5.5, 6.5, 7.5, 8.5 };
	const double got[8] = { a0, a1, a2, a3, a4, a5, a6, a7 };
	int i, mask = 0;

	for (i = 0; i < 8; i++) {
		if (got[i] != expected[i]) {
			printf("uprobe_test_lib_fp_args: arg %d is %g, expected %g\n", i, got[i], expected[i]);
			mask |= 1 << i;
		}
	}
	printf("uprobe_test_lib_fp_args called, mismatch mask: 0x%x\n", mask);
	return mask;
}

int uprobe_test_lib()
{
	printf("uprobe_test_lib called\n");
	return 0;
}

int uprobe_test_lib_arg1(int a1)
{
	printf("uprobe_test_lib_arg1 called\n");
	return 0;
}

int uprobe_test_lib_arg2(char a1, short a2)
{
	printf("uprobe_test_lib_arg2 called\n");
	return 0;
}

int uprobe_test_lib_arg3(unsigned long a1, unsigned int a2, void *a3)
{
	printf("uprobe_test_lib_arg3 called\n");
	return 0;
}

int uprobe_test_lib_arg4(long a1, int a2, char a3, void *a4)
{
	printf("uprobe_test_lib_arg4 called\n");
	return 0;
}

int uprobe_test_lib_arg5(int a1, char a2, unsigned long a3, short a4, void *a5)
{
	printf("uprobe_test_lib_arg5 called\n");
	return 0;
}

int uprobe_test_lib_string_arg(char *str)
{
	printf("uprobe_test_lib_string_arg called\n");
	return 0;
}

// This will be used for Override argNewSymbol test
int uprobe_test_lib_string_arg__(char *str)
{
	printf("uprobe_test_lib_string_arg__ called\n");
	return 1; // fixed return code to be used by tests
}

int uprobe_test_lib_string_arg0(char *str, int two, int three, int four, int five)
{
	printf("uprobe_test_lib_string_arg0 called\n");
	return 0;
}

int uprobe_test_lib_string_arg1(int one, char *str, int three, int four, int five)
{
	printf("uprobe_test_lib_string_arg1 called\n");
	return 0;
}

int uprobe_test_lib_string_arg2(int one, int two, char *str, int four, int five)
{
	printf("uprobe_test_lib_string_arg2 called\n");
	return 0;
}

int uprobe_test_lib_string_arg3(int one, int two, int three, char *str, int five)
{
	printf("uprobe_test_lib_string_arg3 called\n");
	return 0;
}

int uprobe_test_lib_string_arg4(int one, int two, int three, int four, char *str)
{
	printf("uprobe_test_lib_string_arg4 called\n");
	return 0;
}

int uprobe_test_lib_string_arg_empty(char *str)
{
	printf("uprobe_test_lib_string_arg_empty called\n");
	return 0;
}

int uprobe_test_lib_string_arg_null(char *str)
{
	printf("uprobe_test_lib_string_arg_null called\n");
	return 0;
}

int uprobe_test_lib_string_arg_substring(char *str)
{
	printf("uprobe_test_lib_string_arg_substring called\n");
	return 0;
}

int uprobe_test_lib_callback(int (*callback)(int), int arg)
{
	printf("uprobe_test_lib_callback called\n");
	return callback(arg);
}
