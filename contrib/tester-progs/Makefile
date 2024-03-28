
GCC ?= gcc

PROGS = sigkill-tester \
	capabilities-tester \
	namespace-tester \
	fork-tester \
	dup-tester \
	trigger-test-events \
	sigkill-unprivileged-user-ns-tester \
	nop \
	exit-leader \
	exit-tester \
	exit-code \
	uprobe-test-1 \
	uprobe-test-2 \
	lseek-pipe \
	threads-tester \
	bench-reader \
	threads-exit \
	enforcer-tester \
	drop-privileges \
	getcpu \
	direct-write-tester \
	change-capabilities \
	user-stacktrace

# For now enforcer-tester is compiled to 32-bit only on x86_64 as we want
# to test 32-bit binaries and system calls compatibility layer.
ifeq ($(shell uname -m),x86_64)
	PROGS += enforcer-tester-32
endif

all: $(PROGS)

%: %.c
	$(GCC) -Wall $< -o $@

bench-reader: bench-reader.c
	$(GCC) -Wall $< -o $@ -lpthread

threads-tester: threads-tester.c
	$(GCC) -Wall -fno-inline $< -o $@ -lcap -lpthread

threads-exit: threads-exit.c
	$(GCC) -Wall -fno-inline $< -o $@ -lcap -lpthread

capabilities-tester: capabilities-tester.c
	$(GCC) -Wall $< -o $@ -lcap

change-capabilities: change-capabilities.c
	$(GCC) -Wall $< -o $@ -lcap

exit-tester: exit-tester.c
	$(GCC) -Wall $< -o $@ -lpthread

sigkill-unprivileged-user-ns-tester: sigkill-unprivileged-user-ns-tester.c
	$(GCC) -Wall $< -o $@ -lcap

nop: nop.c
	$(GCC) -Wall $< -o $@ -lpthread

drop-privileges: drop-privileges.c
	$(GCC) -Wall $< -o $@ -lpthread

exit-leader: exit-leader.c
	$(GCC) -Wall $< -o $@ -lpthread

exit-code: exit-code.c
	$(GCC) -Wall $< -o $@ -lpthread

libuprobe.so: uprobe-lib.c
	$(GCC) -Wall -fPIC $< -o $@ -shared

uprobe-test-1: uprobe-test.c libuprobe.so
	$(GCC) -Wall $< -o $@ $(CURDIR)/libuprobe.so

uprobe-test-2: uprobe-test-1
	cp uprobe-test-1 uprobe-test-2

# -m32 is an x86_64 flag.
# NB(kkourt) we compile this as static to avoid the need for ia32 libs in VMs
enforcer-tester-32: enforcer-tester.c
	$(GCC) -Wall -m32 -static $< -o $@

lseek-pipe: FORCE
	go build -o lseek-pipe ./go/lseek-pipe

getcpu: FORCE
	go build -o getcpu ./go/getcpu

user-stacktrace: FORCE
	go build -o user-stacktrace ./go/user-stacktrace

.PHONY: clean
clean:
	rm -f $(PROGS)

FORCE:
