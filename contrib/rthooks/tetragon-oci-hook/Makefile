# Copyright 2017-2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

GO ?= go

.PHONY: vendor
vendor:
	$(GO) mod tidy
	$(GO) mod vendor
	$(GO) mod verify
