//go:build ignore
#include <stdlib.h>
#include "usdt.h"

int main(int argc, char **argv)
{
	volatile int return_val = 0;
	int arg_1, arg_2;

	if (argc != 3)
		return -1;

	arg_1 = atoi(argv[1]);
	arg_2 = atoi(argv[2]);

	USDT(tetragon, test, return_val, arg_1, arg_2);
	return return_val;
}
