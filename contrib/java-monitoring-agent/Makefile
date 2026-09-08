# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Tetragon

JAVA_HOME ?= $(shell dirname $$(dirname $$(readlink -f $$(command -v javac))))
ASM_JAR ?=
ASM_COMMONS_JAR ?=

JAVAC := $(JAVA_HOME)/bin/javac
JAR := $(JAVA_HOME)/bin/jar
CLASSES := build/classes
SAMPLE_CLASSES := build/sample
AGENT := tetragon-java-monitoring-agent.jar

.PHONY: all sample test clean check-vars
all: check-vars $(AGENT)

check-vars:
	@test -n "$(ASM_JAR)" || (echo "ASM_JAR must point to asm-9.x.jar" >&2; exit 1)
	@test -n "$(ASM_COMMONS_JAR)" || (echo "ASM_COMMONS_JAR must point to asm-commons-9.x.jar" >&2; exit 1)

$(AGENT): $(shell find src -name '*.java')
	rm -rf $(CLASSES)
	mkdir -p $(CLASSES)
	$(JAVAC) --release 22 -cp $(ASM_JAR):$(ASM_COMMONS_JAR) -d $(CLASSES) $^
	printf 'Premain-Class: io.tetragon.javaagent.TetragonAgent\nCan-Redefine-Classes: false\nCan-Retransform-Classes: false\n' > $(CLASSES)/MANIFEST.MF
	$(JAR) --create --file $@ --manifest $(CLASSES)/MANIFEST.MF -C $(CLASSES) .

sample:
	rm -rf $(SAMPLE_CLASSES)
	mkdir -p $(SAMPLE_CLASSES)
	$(JAVAC) --release 22 -d $(SAMPLE_CLASSES) sample/Sample.java

test: all
	mkdir -p build/test
	$(JAVAC) --release 22 -cp $(CLASSES):$(ASM_JAR):$(ASM_COMMONS_JAR) -d build/test $$(find test -name '*.java')
	$(JAVA_HOME)/bin/java -cp build/test:$(CLASSES):$(ASM_JAR):$(ASM_COMMONS_JAR) io.tetragon.javaagent.AgentUnitTest

clean:
	rm -rf build $(AGENT)
