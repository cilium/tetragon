# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Tetragon

# renovate: datasource=docker
HELM_IMAGE=docker.io/alpine/helm:3.15.2@sha256:61185768b41810085cb57a9bc8de9003bea78ac0dd417e5b0b16223a6a0aa812
# renovate: datasource=docker
KUBECONFORM_IMAGE=ghcr.io/yannh/kubeconform:v0.6.6-alpine@sha256:47141997365b1f6aa914b2e801cb9772b94c2696c279e2046a4517d5bfd8a09a
# renovate: datasource=docker
HELMDOCS_IMAGE=docker.io/jnorwood/helm-docs:v1.14.2@sha256:7e562b49ab6b1dbc50c3da8f2dd6ffa8a5c6bba327b1c6335cc15ce29267979c

REPO_ROOT := $(shell git rev-parse --show-toplevel)
TETRAGON_CHART := tetragon
CRDS := $(REPO_ROOT)/pkg/k8s/apis/cilium.io/client/crds/v1alpha1

HELM ?= docker run --rm -v $(CURDIR)/$(TETRAGON_CHART):/apps $(HELM_IMAGE)

.PHONY: all
all: deps $(TETRAGON_CHART)/crds-yaml lint docs

.PHONY: deps
deps: 
	$(HELM) dependency update .

.PHONY: lint
lint:
	$(HELM) lint . --with-subcharts
	$(HELM) template tetragon . | docker run --rm -i $(KUBECONFORM_IMAGE) --strict --schema-location default

.PHONY: docs
docs:
	docker run --rm -v $(CURDIR)/$(TETRAGON_CHART):/helm-docs -u $$(id -u) $(HELMDOCS_IMAGE)
	./export-doc.sh $(REPO_ROOT)/docs/content/en/docs/reference/helm-chart.md

# NB: Helm has an "official" way to install CRDs which requires simply putting
# them in the crds directory. This method doesn't prevents accidental deletion
# of custom resources, because it doesn't delete CRDs when the chart is
# uninstalled. However, it doesn't support CRD upgrades, which is why we opt to
# install CRDs alongside other resources. This means we can't put them in the
# crds directory, so we name in crds-yaml instead.
.PHONY: $(TETRAGON_CHART)/crds-yaml
$(TETRAGON_CHART)/crds-yaml: $(CRDS)
	cp -rf $(CRDS)/. $(TETRAGON_CHART)/crds-yaml
