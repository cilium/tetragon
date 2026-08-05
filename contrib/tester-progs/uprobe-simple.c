#include <stdio.h>

int
__attribute__((noinline))
pizza(int c)
{
	return c;
}

int
__attribute__((noinline))
lasagna(int c)
{
	return c - 10;
}

int
main(int argc, char *argv[])
{
	int ret = pizza(0);
	printf("pizza() returned %d\n", ret);
	return ret;
}
