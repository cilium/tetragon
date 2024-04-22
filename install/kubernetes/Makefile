# Variables

# renovate: datasource=docker
HELM_IMAGE=docker.io/alpine/helm:3.14.4@sha256:599abc4bc6fc6a7aae894fa726008d78061e8d109f0cc49e16445757d0034cfa
# renovate: datasource=docker
KUBECONFORM_IMAGE=ghcr.io/yannh/kubeconform:v0.6.4-alpine@sha256:051e9bc943ff03de140e85522b5adb8f8d014b67f98582df80b29d3303fec75d
# renovate: datasource=docker
HELMDOCS_IMAGE=docker.io/jnorwood/helm-docs:v1.13.1@sha256:717bd8f770bd1d25ccf79c876f1420e105832f2d6bbde12170405f58f540cb2d

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
