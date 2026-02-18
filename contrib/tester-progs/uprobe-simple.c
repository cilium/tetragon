#include <stdio.h>

int
__attribute__((noinline))
pizza()
{
	return 0;
}

int
main(int argc, char *argv[])
{
	int ret = pizza();
	printf("pizza() returned %d\n", ret);
	return ret;
}
