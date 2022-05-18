
GCC ?= gcc

PROGS = sigkill-tester capabilities-tester namespace-tester

all: $(PROGS)

sigkill-tester: sigkill-tester.c
	$(GCC) -Wall -o sigkill-tester sigkill-tester.c

capabilities-tester: capabilities-tester.c
	$(GCC) -Wall $< -o $@ -lcap

namespace-tester: namespace-tester.c
	$(GCC) -Wall $< -o $@

.PHONY: clean
clean:
	rm -f $(PROGS)
