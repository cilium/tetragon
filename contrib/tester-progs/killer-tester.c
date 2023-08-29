#include <stdio.h>
#include <sys/prctl.h>
#include <errno.h>

int main(void)
{
	prctl(0xffff, 0, 0, 0, 0);
	return errno;
}
