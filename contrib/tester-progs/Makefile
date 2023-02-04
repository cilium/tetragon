
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
	uprobe-test-1 \
	uprobe-test-2

all: $(PROGS)

%: %.c
	$(GCC) -Wall $< -o $@

capabilities-tester: capabilities-tester.c
	$(GCC) -Wall $< -o $@ -lcap

exit-tester: exit-tester.c
	$(GCC) -Wall $< -o $@ -lpthread

sigkill-unprivileged-user-ns-tester: sigkill-unprivileged-user-ns-tester.c
	$(GCC) -Wall $< -o $@ -lcap

exit-leader: exit-leader.c
	$(GCC) -Wall $< -o $@ -lpthread

libuprobe.so: uprobe-lib.c
	$(GCC) -Wall -fPIC $< -o $@ -shared

uprobe-test-1: uprobe-test.c libuprobe.so
	$(GCC) -Wall $< -o $@ $(CURDIR)/libuprobe.so

uprobe-test-2: uprobe-test-1
	cp uprobe-test-1 uprobe-test-2

.PHONY: clean
clean:
	rm -f $(PROGS)
