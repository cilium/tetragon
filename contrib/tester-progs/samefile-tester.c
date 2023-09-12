#include <stdio.h>
int main(int argc, char **argv)
{
	if (argc != 2)
		return 1;

	FILE *file = fopen(argv[1], "w");
	if (file == NULL)
		return 2;

	fprintf(file, "foobar");
	fclose(file);

	return 0;
}
