# Variables
SCRIPT_DIR := $(shell dirname "$(realpath $(lastword $(MAKEFILE_LIST)))")
TETRAGON_CHART := $(SCRIPT_DIR)/tetragon
HELM ?= docker run --rm -v $(TETRAGON_CHART):/apps alpine/helm:3.3.4

# Targets
.PHONY: all lint docs
all: deps lint docs

deps: 
	$(HELM) dependency update .

lint:
	$(HELM) lint . --with-subcharts
	$(HELM) template tetragon . | docker run --rm -i ghcr.io/yannh/kubeconform:v0.6.4-alpine@sha256:e68a0b638c6e9b76f1b7d58b4ec94340ef3b6601db25b2e40b29e3ac2d68e4bf --strict --schema-location default

docs:
	docker run --rm -v $(TETRAGON_CHART):/helm-docs -u $$(id -u) jnorwood/helm-docs:v1.11.0@sha256:66c8f4164dec860fa5c1528239c4aa826a12485305b7b224594b1a73f7e6879a
	$(SCRIPT_DIR)/export-doc.sh $(SCRIPT_DIR)/../../docs/content/en/docs/reference/helm-chart.md
