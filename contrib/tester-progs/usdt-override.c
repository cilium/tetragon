//go:build ignore
#include <stdlib.h>
#include "usdt.h"

int main(int argc, char **argv)
{
	volatile char return_1B = 0;
	volatile short return_2B = 0;
	volatile int return_4B = 0;
	volatile long return_8B = 0;
	int arg_1, arg_2;

	if (argc != 3)
		return -1;

	arg_1 = atoi(argv[1]);
	arg_2 = atoi(argv[2]);

	USDT(tetragon, test_1B, return_1B, arg_1, arg_2);
	USDT(tetragon, test_2B, return_2B, arg_1, arg_2);
	USDT(tetragon, test_4B, return_4B, arg_1, arg_2);
	USDT(tetragon, test_8B, return_8B, arg_1, arg_2);

	return return_4B;
}
