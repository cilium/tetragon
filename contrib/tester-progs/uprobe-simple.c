#include <stdio.h>

int
__attribute__((noinline))
pizza()
{
	return 0;
}

int
__attribute__((noinline))
burger()
{
	return 0;
}

int
main(int argc, char *argv[])
{
	int ret = pizza();
	printf("pizza() returned %d\n", ret);
	printf("burger() returned %d\n", burger());
	return ret;
}
