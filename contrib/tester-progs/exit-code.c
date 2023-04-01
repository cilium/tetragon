#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv)
{
	char *arg = argv[1];

	// convert the argument to an integer
	int exit_code = atoi(arg);

	// do something with the argument
	printf("The exit code is %d\n", exit_code);
	return exit_code;
}
