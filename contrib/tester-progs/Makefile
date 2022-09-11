
GCC ?= gcc

PROGS = sigkill-tester \
	capabilities-tester \
	namespace-tester \
	fork-tester \
	dup-tester \
	trigger-test-events \
	sigkill-unprivileged-user-ns-tester \
	nop

all: $(PROGS)

%: %.c
	$(GCC) -Wall $< -o $@

capabilities-tester: capabilities-tester.c
	$(GCC) -Wall $< -o $@ -lcap

sigkill-unprivileged-user-ns-tester: sigkill-unprivileged-user-ns-tester.c
	$(GCC) -Wall $< -o $@ -lcap

.PHONY: clean
clean:
	rm -f $(PROGS)
