#include <stdio.h>
#include <stdlib.h>

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
__attribute__((noinline))
manyargs(int zero, int one, int two, int three, int four, int five, int six, int seven, int retargidx)
{
	printf("manyargs was passed: %d,%d,%d,%d,%d,%d,%d,%d and retargidx: %d\n", zero, one, two, three, four, five, six, seven, retargidx);

	switch (retargidx) {
		case 0:
			return zero;
		case 1:
			return one;
		case 2:
			return two;
		case 3:
			return three;
		case 4:
			return four;
		case 5:
			return five;
		case 6:
			return six;
		case 7:
			return seven;
		default:
			fprintf(stderr, "regargidx must be between 0 and 7");
			return -1;
	}
}

int
main(int argc, char *argv[])
{
	int ret = pizza(0);
	printf("pizza() returned %d\n", ret);

	if (argc == 2) {
		ret = manyargs(0, 1, 2, 3, 4, 5, 6, 7, (int)strtol(argv[1], NULL, 10));
	}

	return ret;
}
