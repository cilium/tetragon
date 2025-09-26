#ifdef __x86_64__
#include <sys/io.h>

int main()
{
	unsigned long io_delay = 0x80;
	int ret;

	ret = ioperm(io_delay, 1, 1);
	if (ret < 0)
		return 1;
	ioperm(io_delay, 1, 0);
	return 0;
}
#else
int main()
{
	return 0;
}
#endif

