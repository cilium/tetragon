#include <signal.h>

int main(int argc, char **argv)
{
	raise(SIGKILL);
}
