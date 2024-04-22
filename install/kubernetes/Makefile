# Variables

# renovate: datasource=docker
HELM_IMAGE=docker.io/alpine/helm:3.14.4@sha256:599abc4bc6fc6a7aae894fa726008d78061e8d109f0cc49e16445757d0034cfa
# renovate: datasource=docker
KUBECONFORM_IMAGE=ghcr.io/yannh/kubeconform:v0.6.4-alpine@sha256:e68a0b638c6e9b76f1b7d58b4ec94340ef3b6601db25b2e40b29e3ac2d68e4bf
# renovate: datasource=docker
HELMDOCS_IMAGE=jnorwood/helm-docs:v1.11.0@sha256:66c8f4164dec860fa5c1528239c4aa826a12485305b7b224594b1a73f7e6879a

SCRIPT_DIR := $(shell dirname "$(realpath $(lastword $(MAKEFILE_LIST)))")
TETRAGON_CHART := $(SCRIPT_DIR)/tetragon
HELM ?= docker run --rm -v $(TETRAGON_CHART):/apps $(HELM_IMAGE)

# Targets
.PHONY: all lint docs
all: deps lint docs

deps: 
	$(HELM) dependency update .

lint:
	$(HELM) lint . --with-subcharts
	$(HELM) template tetragon . | docker run --rm -i $(KUBECONFORM_IMAGE) --strict --schema-location default

docs:
	docker run --rm -v $(TETRAGON_CHART):/helm-docs -u $$(id -u) $(HELMDOCS_IMAGE)
	$(SCRIPT_DIR)/export-doc.sh $(SCRIPT_DIR)/../../docs/content/en/docs/reference/helm-chart.md
