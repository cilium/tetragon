# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Tetragon

# renovate: datasource=docker
HELM_IMAGE=docker.io/alpine/helm:3.15.1@sha256:6ae53e937e5f3462f684d9ff159e6f83f978f00a4c5ab2181c76e06621742197
# renovate: datasource=docker
KUBECONFORM_IMAGE=ghcr.io/yannh/kubeconform:v0.6.6-alpine@sha256:47141997365b1f6aa914b2e801cb9772b94c2696c279e2046a4517d5bfd8a09a
# renovate: datasource=docker
HELMDOCS_IMAGE=docker.io/jnorwood/helm-docs:v1.13.1@sha256:717bd8f770bd1d25ccf79c876f1420e105832f2d6bbde12170405f58f540cb2d

REPO_ROOT := $(shell git rev-parse --show-toplevel)
TETRAGON_CHART := tetragon
CRDS := $(REPO_ROOT)/pkg/k8s/apis/cilium.io/client/crds/v1alpha1

HELM ?= docker run --rm -v ./$(TETRAGON_CHART):/apps $(HELM_IMAGE)

.PHONY: all
all: deps $(TETRAGON_CHART)/templates/crds lint docs

.PHONY: deps
deps: 
	$(HELM) dependency update .

.PHONY: lint
lint:
	$(HELM) lint . --with-subcharts
	$(HELM) template tetragon . | docker run --rm -i $(KUBECONFORM_IMAGE) --strict --schema-location default

.PHONY: docs
docs:
	docker run --rm -v ./$(TETRAGON_CHART):/helm-docs -u $$(id -u) $(HELMDOCS_IMAGE)
	./export-doc.sh $(REPO_ROOT)/docs/content/en/docs/reference/helm-chart.md

# NB: Helm has an "official" way to install CRDs which requires simply putting
# them in the top-level crds directory. This method prevents accidental deletion
# of custom resources, because it doesn't delete CRDs when the chart is
# uninstalled. However, it doesn't support CRD upgrades, which is why we opt to
# install CRDs alongside other resources.
.PHONY: $(TETRAGON_CHART)/templates/crds
$(TETRAGON_CHART)/templates/crds: $(CRDS)
	mkdir -p $@
	for file in $(CRDS)/*.yaml; do \
		template_file="$@/$$(basename $$file)"; \
		echo "{{- if eq .Values.crds.installMethod \"helm\" }}" > "$$template_file"; \
		cat "$$file" >> "$$template_file"; \
		echo "{{- end }}" >> "$$template_file"; \
	done
