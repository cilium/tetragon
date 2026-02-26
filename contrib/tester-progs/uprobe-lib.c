#include <stdio.h>

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

int uprobe_test_lib_string_arg_empty(char *str)
{
	printf("uprobe_test_lib_string_arg_empty called\n");
	return 0;
}
