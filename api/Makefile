# Copyright 2017-2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include ../Makefile.defs

EXTRA_BUF_FLAGS ?=

.PHONY: all
all: 

# FIXME: re-enable lint on the all target once we have a chance to fix the lints
.PHONY: __all_local
__all_local: __format_local __check-breaking_local __proto_local #__lint_local 

.PHONY: __proto_local
__proto_local: 
	$(BUF) generate $(EXTRA_BUF_FLAGS)

.PHONY: __lint_local
__lint_local:
	$(BUF) lint $(EXTRA_BUF_FLAGS)

.PHONY: __format_local
__format_local:
	$(BUF) format -w $(EXTRA_BUF_FLAGS)

.PHONY: __check-breaking_local
__check-breaking_local:
	$(BUF) breaking /src/api --against "$(CURDIR)/../.git#branch=$(BUF_BREAKING_AGAINST_BRANCH),subdir=api/v1" $(EXTRA_BUF_FLAGS)

.PHONY: proto lint format check-breaking
all proto lint format check-breaking:
	../contrib/scripts/repo-docker-run.sh --rm \
		--volume $(CURDIR)/..:/src \
		--workdir /src/api \
		--user "$(shell id -u):$(shell id -g)" \
		$(BUILDER_IMAGE) \
		make -C /src/api __$@_local BUF_BREAKING_AGAINST_BRANCH=$(BUF_BREAKING_AGAINST_BRANCH) 

.PHONY: debug
debug:
	@echo ../contrib/scripts/repo-docker-run.sh --rm \
		--volume $(CURDIR)/..:/src \
		--workdir /src/api \
		--user "$(shell id -u):$(shell id -g)" \
		$(BUILDER_IMAGE) \
		buf $(EXTRA_BUF_FLAGS)

.PHONY: vendor
vendor:
	$(GO) mod tidy
	$(GO) mod vendor
	$(GO) mod verify