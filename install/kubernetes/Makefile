# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Tetragon

# renovate: datasource=docker
HELM_IMAGE=docker.io/alpine/helm:3.15.3@sha256:ba0dcbbcf31f780bd8cdeeabc44bc6939df695a725c90dbb25762ada2f6e3df0
# renovate: datasource=docker
KUBECONFORM_IMAGE=ghcr.io/yannh/kubeconform:v0.6.7-alpine@sha256:824e0c248809e4b2da2a768b16b107cf17ada88a89ec6aa6050e566ba93ebbc6
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
