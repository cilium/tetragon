# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Tetragon

JAVA_HOME ?= $(shell dirname $$(dirname $$(readlink -f $$(command -v javac))))
CC ?= cc
OUT ?= tetragon-jvmti.so
CPPFLAGS += -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux -I../../../jvmti
CFLAGS ?= -O2 -g
CFLAGS += -fPIC -fvisibility=hidden -Wall -Wextra -Werror -std=gnu11
LDFLAGS += -shared -pthread

.PHONY: all clean
all: $(OUT)

SRCS := jvmti_agent.c classfile.c

$(OUT): $(SRCS) classfile.h ../../../jvmti/proto.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $(SRCS) $(LDFLAGS)

# Test driver for the class file rewriter, used by the tests in
# pkg/javaattach. It does not need the JVM headers.
TEST_OUT ?= classfile-test
TEST_CFLAGS ?= -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=undefined

.PHONY: test-driver
test-driver: $(TEST_OUT)

$(TEST_OUT): classfile-test.c classfile.c classfile.h
	$(CC) -Wall -Wextra -Werror -std=gnu11 $(TEST_CFLAGS) -o $@ classfile-test.c classfile.c

clean:
	rm -f $(OUT) $(TEST_OUT)
