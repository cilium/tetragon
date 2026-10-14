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

clean:
	rm -f $(OUT)
