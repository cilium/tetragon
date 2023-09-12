
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
	samefile-tester \
	bench-reader \
	threads-exit \
	killer-tester

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

exit-tester: exit-tester.c
	$(GCC) -Wall $< -o $@ -lpthread

sigkill-unprivileged-user-ns-tester: sigkill-unprivileged-user-ns-tester.c
	$(GCC) -Wall $< -o $@ -lcap

nop: nop.c
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

lseek-pipe: FORCE
	go build -o lseek-pipe ./go/lseek-pipe

.PHONY: clean
clean:
	rm -f $(PROGS)

FORCE:
