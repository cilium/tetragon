GO ?= go

all: tetragon-tester tetragon-vmtests-run

tetragon-tester: FORCE
	$(GO) build ../../cmd/tetragon-tester

tetragon-vmtests-run: FORCE
	$(GO) build ../../cmd/tetragon-vmtests-run

FORCE:
