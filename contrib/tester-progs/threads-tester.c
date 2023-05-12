#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/capability.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <dirent.h>

#define FILENAME "/etc/issue"

#define errExit(msg) \
	do { \
		perror(msg); \
		exit(EXIT_FAILURE); \
	} while (0)

extern char *optarg;
static const char *arg_sensor = NULL;

const int whence_bogus_value = 4444;
const int fd_bogus_value = -1;
const int exit_thread_code = 255;

enum {
	DEFAULT_EXEC,
	KPROBE,
	TRACEPOINT,
	UPROBE,
	EXIT,
};

/* Use direct syscalls and avoid NPTL POSIX standard */
static inline pid_t sys_gettid(void)
{
	return (pid_t)syscall(__NR_gettid);
}

static void do_open(const char *process, const char *pathname)
{
	FILE *fptr = fopen(pathname, "r");
	if(fptr == NULL)
		errExit("fopen");

	printf("%s\t(pid:%d, tid:%d, ppid:%d)\topen(\"%s\") succeeded\n", process, getpid(), sys_gettid(), getppid(), pathname);
	fclose(fptr);
}

static void do_lseek(const char *process)
{
	lseek(fd_bogus_value, 0, whence_bogus_value);
	printf("%s\t(pid:%d, tid:%d, ppid:%d)\tlseek() performed\n", process, getpid(), sys_gettid(), getppid());
}

void do_uprobe(const char *process)
{
	printf("%s\t(pid:%d, tid:%d, ppid:%d)\tdo_uprobe() performed\n", process, getpid(), sys_gettid(), getppid());
}

static void *thread(void *arg)
{
	do_open("Thread 1:", FILENAME);

	fflush(stdout);
	return 0;
}

static void *thread_tracepoint(void *arg)
{
	do_lseek("Thread 1:");
	fflush(stdout);
	return 0;
}

static void *thread_uprobe(void *args)
{
	do_uprobe("Thread 1:");
	fflush(stdout);
	return 0;
}

// This is used mostely for debugging
void thread_exit_sig_handler(int sig)
{
	printf("Thread 1: received signal %d\n", sig);
}

static void *thread_exit(void *args)
{
	int cnt = 5;

	// Use SIGCONT to easily inspect logs, debug and assert that
	// we printed the received signal, and make it per thread.
	signal(SIGCONT, thread_exit_sig_handler);

	while (cnt--) {
		sleep(1);
	}

	do_open("Thread 1:", FILENAME);
	fflush(stdout);

	// Do another round of sleep to allow test to check that task is
	// still active, then ensure it is removed and we receive the
	// exit event. All of this without an explicit execve call.
	cnt = 5;
	while (cnt--) {
		sleep(1);
	}

	fflush(stdout);

	// After last thread terminates the process will always exit(0) so
	// let's explicitly exit with a non zero to assert
	// thread/process/exit_status
	exit(exit_thread_code);
}

static void default_exec()
{
	pthread_t ttid;

	pthread_create(&ttid, NULL, thread, NULL);
	fflush(stdout);
	pthread_join(ttid, NULL);

	do_open("Child 1:", FILENAME);

	fflush(stdout);
}

static void kprobe()
{
	// Default exec and kprobe sensors need same events
	default_exec();
}

static void tracepoint()
{
	pthread_t ttid;

	pthread_create(&ttid, NULL, thread_tracepoint, NULL);
	fflush(stdout);
	pthread_join(ttid, NULL);

	do_lseek("Child 1:");

	fflush(stdout);
}

static void uprobe()
{
	pthread_t ttid;

	pthread_create(&ttid, NULL, thread_uprobe, NULL);
	fflush(stdout);
	pthread_join(ttid, NULL);

	do_uprobe("Child 1:");

	fflush(stdout);
}

// Thread leader will exit before new thread which will wait, do an open then thread_exit
// This test makes sense when it is trigerred from go tests.
static void handle_exit()
{
	pthread_t ttid;
	do_open("Child 1:", FILENAME);
	pthread_create(&ttid, NULL, thread_exit, NULL);

	fflush(stdout);
	int ret = 0;
	pthread_exit(&ret);
}

static void help(char *prog) {

        printf("%s [--sensor name]\n"
		"  -h, --help		Show this help\n"
		"  -s, --sensor=name	Run test for the sensor specified by name\n"
		"			name can be: exec exit kprobe tracepoint uprobe\n"
		"     			example:  --sensor=exec\n",
		prog);
}


int main(int argc, char *argv[])
{
	pid_t pid;
	int c, sensor = DEFAULT_EXEC;

	static const struct option options[] = {
		{ "help",	no_argument,		NULL,	'h'	},
		{ "sensor",	required_argument,	NULL,	's'	},
		{}
	};

	while ((c = getopt_long(argc, argv, "hs:", options, NULL)) >= 0)
		switch (c) {
		case 'h':
			help(argv[0]);
			return 0;
		case 's':
			arg_sensor = optarg;
			break;
		case '?':
			help(argv[0]);
			return -EINVAL;
		}

	if (arg_sensor) {
		if (strncmp(arg_sensor, "exec", 4) == 0)
			sensor = DEFAULT_EXEC;
		else if (strncmp(arg_sensor, "kprobe", 4) == 0)
			sensor = KPROBE;
		else if (strncmp(arg_sensor, "tracepoint", 10) == 0)
			sensor = TRACEPOINT;
		else if (strncmp(arg_sensor, "uprobe", 6) == 0)
			sensor = UPROBE;
		else if (strncmp(arg_sensor, "exit", 4) == 0)
			sensor = EXIT;
		else {
			printf("%s invalid sensor name: '%s'\n", argv[0], arg_sensor);
			help(argv[0]);
			return -EINVAL;
		}
	}

	printf("parent:\t\t(pid:%d, tid:%d, ppid:%d)\tstarts\n", getpid(), sys_gettid(), getppid());

	if  ((pid = fork()) == -1) {
		perror("fork");
		exit(1);
	} else if (pid == 0) {
		switch (sensor) {
		case DEFAULT_EXEC:
			default_exec();
			break;
		case KPROBE:
			kprobe();
			break;
		case TRACEPOINT:
			tracepoint();
			break;
		case UPROBE:
			uprobe();
			break;
		case EXIT:
			handle_exit();
			break;
		}
		return 0;
	}

	if (sensor == EXIT) {
		siginfo_t infop;
		int ret = waitid(P_ALL, -1, &infop, WEXITED|WCONTINUED);
		if (ret < 0) {
			errExit("failed at test sensor 'exit' waittid(): ");
		}
		printf("parent:\t\t(pid:%d, tid:%d, ppid:%d)\tchild1 (%d) exited with: %d\n", getpid(), sys_gettid(), getppid(), infop.si_pid, infop.si_status);
		if (infop.si_pid != pid) {
			printf("Error: waitid() returned different PID %d != %d\n", pid, infop.si_pid);
			exit(-EINVAL);
		}
		if (infop.si_status != exit_thread_code)  {
			printf("Error: waitid() returned unxpected status code: %d != %d\n", exit_thread_code, infop.si_status);
			exit(-EINVAL);
		}
		if (infop.si_code != CLD_EXITED) {
			printf("Error: waitid() returned unxpected code: %d != %d\n", CLD_KILLED, infop.si_code);
			exit(-EINVAL);
		}
		exit(exit_thread_code);
	} else {
		int process_wait;
		pid_t pid2 = waitpid(-1, &process_wait, WEXITED);
		printf("parent:\t\t(pid:%d, tid:%d, ppid:%d)\tchild1 (%d) exited with: %d\n", getpid(), sys_gettid(), getppid(), pid2, process_wait);
		if (pid2 != pid) {
			printf("Error: wait returned different PID %d != %d\n", pid, pid2);
			exit(-EINVAL);
		}
	}

	return 0;
}
