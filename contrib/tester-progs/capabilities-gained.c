#include <sys/capability.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#define die(x) do {                                                                     \
	fprintf(stderr, "[%s:%d]: %s: %s\n", __FILE__, __LINE__, x, strerror(errno)); \
	exit(1);                                                                        \
} while (0)

/**
 * capabilities-gained: perform three capset() syscalls, with only one matching the capability
 * gained operator
 */
int main(int argc, char **argv)
{
	const cap_value_t cap_list[1] = {CAP_NET_RAW};
	cap_flag_value_t value;
	cap_t caps;
	int err;

	/* read caps and ensure CAP_NET_RAW is set */
	caps = cap_get_proc();
	if (caps == NULL)
		die("cap_set_proc");

	cap_get_flag(caps, CAP_NET_RAW, CAP_EFFECTIVE, &value);
	if (value != CAP_SET) {
		fprintf(stderr, "[%s:%d] CAP_NET_RAW not set, bailing out\n", __FILE__, __LINE__);
		exit(1);
	}


	/* set the same value (capset #1) */
	err = cap_set_proc(caps);
	if (err == -1)
		die("cap_set_proc");


	/* clear CAP_NET_RAW and set caps (capset #2) */
	err = cap_set_flag(caps, CAP_EFFECTIVE, 1, cap_list, CAP_CLEAR);
	if (err == -1)
		die("cap_set_flag");
	err = cap_set_proc(caps);
	if (err == -1)
		die("cap_set_proc");


	/* clear CAP_NET_RAW and set caps (capset #3) */
	err = cap_set_flag(caps, CAP_EFFECTIVE, 1, cap_list, CAP_SET);
	if (err == -1)
		die("cap_set_flag");
	err = cap_set_proc(caps);
	if (err == -1)
		die("cap_set_proc");
}
