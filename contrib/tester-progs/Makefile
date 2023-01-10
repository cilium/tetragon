
GCC ?= gcc

PROGS = sigkill-tester \
	capabilities-tester \
	namespace-tester \
	fork-tester \
	dup-tester \
	trigger-test-events \
	sigkill-unprivileged-user-ns-tester \
	sigkill-rawio-syscalls-group-tester \
	sigkill-module-syscalls-group-tester \
	nop

all: $(PROGS) make_kernel_module

%: %.c
	$(GCC) -Wall $< -o $@

capabilities-tester: capabilities-tester.c
	$(GCC) -Wall $< -o $@ -lcap

sigkill-unprivileged-user-ns-tester: sigkill-unprivileged-user-ns-tester.c
	$(GCC) -Wall $< -o $@ -lcap

sigkill-rawio-syscalls-group-tester: sigkill-rawio-syscalls-group-tester.c
	$(GCC) -Wall $< -o $@ -lcap

sigkill-module-syscalls-group-tester: sigkill-module-syscalls-group-tester.c
	$(GCC) -Wall $< -o $@ -lcap

obj-m += kernel_module_hello.o

KDIR := /lib/modules/$(shell uname -r)/build

.PHONY: make_kernel_module
make_kernel_module:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

.PHONY: clean_kernel_module
clean_kernel_module:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

.PHONY: clean
clean: clean_kernel_module
	rm -f $(PROGS)
