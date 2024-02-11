#include <stdio.h>
#include <sys/prctl.h>
#include <errno.h>
#include <stdlib.h>
#include <limits.h>

int main(int argc, char **argv)
{
	long long num = 0xffff;

	if (argc == 2) {
		num = strtoll(argv[1], NULL, 16);
		if (num == LONG_MIN)
			return -EINVAL;
	}
	prctl(num, 0, 0, 0, 0);
	return errno;
}
