#include <stdio.h>

static int __attribute__ ((noinline)) test1(void)
{
	return -1;
}

int main(int argc, char **argv)
{
	printf("test1 = %d\n", test1());
	getchar();
	return 0;
}
