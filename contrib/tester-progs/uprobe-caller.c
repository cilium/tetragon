#include <stdio.h>

int uprobe_test_lib_callback(int (*callback)(int), int arg);

__attribute__((noinline)) int func3(int a)
{
	return a;
}

__attribute__((noinline)) int func2(int a)
{
	return func3(a);
}

__attribute__((noinline)) int func1(int a)
{
	return func2(a);
}

int main(int argc, char *argv[])
{
	const volatile int a = 1;
	int ret = func1(a);
	printf("func1() returned %d\n", ret);
	ret += func3(a);
	printf("func1() + func3() returned %d\n", ret);
	ret += uprobe_test_lib_callback(func3, a);
	printf("func1() + func3() + callback(func3) returned %d\n", ret);
	return ret;
}
