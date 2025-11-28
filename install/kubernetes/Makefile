# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Tetragon

include ../../Makefile.defs

#
# -- Images
#
# renovate: datasource=docker
HELM_IMAGE = docker.io/alpine/helm:4.0.1@sha256:4677d32ca3ed7181b100c2cb8a75faf4ed46f3a65933309084e8df204a5fa78e
# renovate: datasource=docker
KUBECONFORM_IMAGE = ghcr.io/yannh/kubeconform:v0.7.0-alpine@sha256:8f0eeaaa96ba27ba1500b0e4b1c215acc358d159c62a7ecae58d7a03403287b0
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
HELM_VALUES_OVERRIDE = helm_lint_values_override.yaml
ROOT_DIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
TETRAGON_CHART = tetragon
CRDS_RELATIVE_DIR = pkg/k8s/apis/cilium.io/client/crds/v1alpha1
CRDS := $(ROOT_DIR)/$(CRDS_RELATIVE_DIR)
JSON_SCHEMAS := $(ROOT_DIR)/install/kubernetes/schemas

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
		-v $(CURDIR)/$(HELM_VALUES_OVERRIDE):/$(HELM_VALUES_OVERRIDE) \
		$(HELM_IMAGE)

#
# -- Make targets
#

##@ Build

.PHONY: all
all: docs $(TETRAGON_CHART)/crds-yaml

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

.PHONY: kubeconform
# Run kubeconform Helm chart validation checks to validate the templated
# Kubernetes (custom) resources against their spec.
# To validate potentially included Tetragon CRs in the Helm chart (using
# openapi2jsonschema.py), we need to have the JSON schema of the TracingPolicy
# CRD. Skip validating the Tetragon CRDs themselves (circular dependency).
kubeconform: ## Validate Helm chart using kubeconform
kubeconform:
	mkdir -p $(JSON_SCHEMAS)/
	$(PYTHON) /bin/bash -c "pip install pyyaml && python /code/install/kubernetes/openapi2jsonschema.py /code/$(CRDS_RELATIVE_DIR)/*"
	mv $(ROOT_DIR)/install/kubernetes/*-cilium.io.json $(JSON_SCHEMAS)/
	@echo "## Testing Helm chart: \"$(TETRAGON_CHART)\""
	$(HELM) template $(TETRAGON_CHART) . \
	-f values.yaml \
	-f /$(HELM_VALUES_OVERRIDE) \
	| docker run --rm -i -v $(JSON_SCHEMAS):/schemas $(KUBECONFORM_IMAGE) \
		-summary \
		-verbose \
		-schema-location default \
		-schema-location '/schemas/{{ .ResourceKind }}-{{ .Group }}.json' \
		-skip CustomResourceDefinition \
		-strict \
		-kubernetes-version $(K8S_VERSION)
	rm -rf $(JSON_SCHEMAS)/

##@ Documentation

.PHONY: help
help: ## Display this help, based on https://www.thapaliya.com/en/writings/well-documented-makefiles/
	$(call print_help_from_comments)