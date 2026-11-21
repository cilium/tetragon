# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Tetragon

JAVA_HOME ?= $(shell dirname $$(dirname $$(readlink -f $$(command -v javac))))
CC ?= cc
OUT ?= tetragon-jvmti.so

.PHONY: all clean
all: $(OUT)

$(OUT): jvmti_agent.c
	@test -f "$(JAVA_HOME)/include/jni.h" || { echo "missing JNI headers under JAVA_HOME=$(JAVA_HOME)" >&2; exit 1; }
	$(CC) -O2 -Wall -Wextra -Werror -fPIC -shared -nostdlib -fno-builtin -fno-stack-protector -fno-unwind-tables -fno-asynchronous-unwind-tables \
		-I"$(JAVA_HOME)/include" -I"$(JAVA_HOME)/include/linux" \
		-o "$@" "$<"

clean:
	rm -f $(OUT)
