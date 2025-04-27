
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
	enforcer-tester-32 \
	drop-privileges \
	getcpu \
	direct-write-tester \
	change-capabilities \
	user-stacktrace \
	test-helper \
	pause \
	raisesigkill \
	forks \
	capabilities-gained \
	follow_children_1 \
	usdt


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

capabilities-gained: capabilities-gained.c
	$(GCC) -Wall $< -o $@ -lcap

usdt: usdt.c
	$(GCC) -Wall $< -o $@

# NB: compile the 32 bit version of enforcer-tester statically so that we don't
# need additional libraries in the VMs
enforcer-tester-32: enforcer-tester.c
ifeq ($(shell uname -m),x86_64)
	$(GCC) -Wall -m32 -static $< -o $@
else ifeq ($(shell uname -m),aarch64)
	arm-linux-gnueabihf-gcc -Wall -static $< -o $@
else
	$(error unsupported arch)
endif

lseek-pipe: FORCE
	go build -o lseek-pipe ./go/lseek-pipe

getcpu: FORCE
	go build -o $@ ./go/getcpu

getcpu-i386: FORCE
	GOARCH=386 go build -o $@ ./go/getcpu

user-stacktrace: FORCE
	go build -o user-stacktrace ./go/user-stacktrace

test-helper: FORCE
	go build -o test-helper ./go/test-helper

.PHONY: clean
clean:
	rm -f $(PROGS)

FORCE:
