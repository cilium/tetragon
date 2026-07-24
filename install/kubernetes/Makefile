# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Tetragon

include ../../Makefile.defs

#
# -- Images
#
# renovate: datasource=docker
HELM_IMAGE = docker.io/alpine/helm:4.2.3@sha256:b97ba4f9b27fe7af16ee3d37e6815783c9d4a51289b6240a9024ec471611ae9b
# renovate: datasource=docker
KUBECONFORM_IMAGE = ghcr.io/yannh/kubeconform:v0.8.0-alpine@sha256:6b90a5f23d846140ce0194fe050b1995e546eba938f3a6bf10c039dd5e24588f
# renovate: datasource=docker
HELMDOCS_IMAGE = docker.io/jnorwood/helm-docs:v1.14.2@sha256:7e562b49ab6b1dbc50c3da8f2dd6ffa8a5c6bba327b1c6335cc15ce29267979c
# renovate: datasource=docker
PYTHON_IMAGE = docker.io/python:3.14-slim-bookworm

#
# -- Versions
#
# renovate: datasource=github-releases depName=yannh/kubeconform
KUBECONFORM_VERSION = v0.6.7
K8S_VERSION = master

#
# -- Variables
#
# Each values file in this directory is validated as a separate scenario, on
# top of the chart defaults. Add a file to cover more of the chart.
HELM_VALUES_DIR = kubeconform
HELM_VALUES_FILES = $(notdir $(wildcard $(HELM_VALUES_DIR)/*.yaml))
# Render for the version we validate against, so that version-gated fields
# match the schema. "master" is not a semver, let Helm use its own default.
HELM_KUBE_VERSION = $(if $(filter master,$(K8S_VERSION)),,--kube-version $(K8S_VERSION))
ROOT_DIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
TETRAGON_CHART = tetragon
CRDS_RELATIVE_DIR = pkg/k8s/apis/cilium.io/client/crds/v1alpha1
CRDS := $(ROOT_DIR)/$(CRDS_RELATIVE_DIR)
JSON_SCHEMAS := $(ROOT_DIR)/pkg/tracingpolicy/schemas

#
# -- Commands
#
PYTHON := docker run --rm \
		-v $(ROOT_DIR):/code \
		--workdir=/code/install/kubernetes \
		-e FILENAME_FORMAT='{kind}-{fullgroup}' \
		$(PYTHON_IMAGE)
HELM := docker run --rm -u $(shell id -u):$(shell id -g) \
		-v $(CURDIR)/$(TETRAGON_CHART):/apps \
		-v $(CURDIR)/$(HELM_VALUES_DIR):/$(HELM_VALUES_DIR) \
		$(HELM_IMAGE)

#
# -- Make targets
#

##@ Build

.PHONY: all
all: docs $(TETRAGON_CHART)/crds-yaml $(TETRAGON_CHART)/schemas

.PHONY: docs
docs: ## Generate Helm docs for the README.md
	docker run --rm -v $(CURDIR)/$(TETRAGON_CHART):/helm-docs -u $$(id -u) $(HELMDOCS_IMAGE)
	./export-doc.sh $(ROOT_DIR)/docs/content/en/docs/reference/helm-chart.md

# NB: Helm has an "official" way to install CRDs which requires simply putting
# them in the crds directory. This method doesn't prevents accidental deletion
# of custom resources, because it doesn't delete CRDs when the chart is
# uninstalled. However, it doesn't support CRD upgrades, which is why we opt to
# install CRDs alongside other resources. This means we can't put them in the
# crds directory, so we name in crds-yaml instead.
.PHONY: $(TETRAGON_CHART)/crds-yaml
$(TETRAGON_CHART)/crds-yaml: $(CRDS)
	cp -rf $(CRDS)/. $(TETRAGON_CHART)/crds-yaml

##@ Validation

.PHONY: validation
validation: ## Validate/lint the Helm chart and all its resources
	$(MAKE) lint
	$(MAKE) kubeconform

.PHONY: openapi2jsonschema.py
openapi2jsonschema.py: ## openapi2jsonschema.py script generating JSON schema from the CRD YAML spec.
	curl -sSfLO https://raw.githubusercontent.com/yannh/kubeconform/$(KUBECONFORM_VERSION)/scripts/$@

.PHONY: lint
lint: ## Lint the Helm chart
	$(HELM) lint . --with-subcharts

.PHONY: check-images-tags
check-images-tags: ## Verify all image:tag references in values.yaml exist in their registries
	@set -e; \
	IMAGES=$$(yq -e '.. | select(has("repository") and has("tag")) | .repository + ":" + .tag' tetragon/values.yaml); \
	for img in $$IMAGES; do \
		echo "Checking $$img"; \
		if ! docker buildx imagetools inspect "$$img" >/dev/null 2>&1; then \
			echo "  MISSING: $$img" >&2; \
			exit 1; \
		fi; \
	done;

.PHONY: $(TETRAGON_CHART)/schemas
$(TETRAGON_CHART)/schemas: $(TETRAGON_CHART)/crds-yaml openapi2jsonschema.py ## generate json schema from crds
	mkdir -p $(JSON_SCHEMAS)/
	$(PYTHON) /bin/bash -c "pip install pyyaml && python /code/install/kubernetes/openapi2jsonschema.py /code/$(CRDS_RELATIVE_DIR)/*"
	mv -f $(ROOT_DIR)/install/kubernetes/*-cilium.io.json $(JSON_SCHEMAS)/

.PHONY: kubeconform
# Run kubeconform Helm chart validation checks to validate the templated
# Kubernetes (custom) resources against their spec.
# To validate potentially included Tetragon CRs in the Helm chart (using
# openapi2jsonschema.py), we need to have the JSON schema of the TracingPolicy
# CRD. Skip validating the Tetragon CRDs themselves (circular dependency).
# Skip the cert-manager Certificate too: its schema belongs to cert-manager and
# is not available here.
kubeconform: $(TETRAGON_CHART)/schemas ## Validate Helm chart using kubeconform
	@failed=""; \
	for values in $(HELM_VALUES_FILES); do \
		echo ""; \
		echo "==> $$values (Kubernetes $(K8S_VERSION))"; \
		if $(HELM) template $(TETRAGON_CHART) . \
			$(HELM_KUBE_VERSION) \
			-f values.yaml \
			-f /$(HELM_VALUES_DIR)/$$values \
			| docker run --rm -i -u $(shell id -u):$(shell id -g) \
				-v $(JSON_SCHEMAS):/schemas \
				$(KUBECONFORM_IMAGE) \
				-summary \
				-verbose \
				-schema-location default \
				-schema-location '/schemas/{{ .ResourceKind }}-{{ .Group }}.json' \
				-skip CustomResourceDefinition,Certificate \
				-strict \
				-kubernetes-version $(K8S_VERSION); then \
			echo "==> PASS: $$values"; \
		else \
			echo "==> FAIL: $$values"; \
			failed="$$failed $$values"; \
		fi; \
	done; \
	if [ -n "$$failed" ]; then \
		echo ""; \
		echo "kubeconform failed for:$$failed"; \
		exit 1; \
	fi

##@ Documentation

.PHONY: help
help: ## Display this help, based on https://www.thapaliya.com/en/writings/well-documented-makefiles/
	$(call print_help_from_comments)