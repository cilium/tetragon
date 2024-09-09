# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Tetragon

# renovate: datasource=docker
HELM_IMAGE=docker.io/alpine/helm:3.15.4@sha256:105741fa6621ed9a3ea944066de78bb27d4b9bb93a56ce8e7cb4d621e1e4bbf2
# renovate: datasource=docker
KUBECONFORM_IMAGE=ghcr.io/yannh/kubeconform:v0.6.7-alpine@sha256:824e0c248809e4b2da2a768b16b107cf17ada88a89ec6aa6050e566ba93ebbc6
# renovate: datasource=docker
HELMDOCS_IMAGE=docker.io/jnorwood/helm-docs:v1.14.2@sha256:7e562b49ab6b1dbc50c3da8f2dd6ffa8a5c6bba327b1c6335cc15ce29267979c
# renovate: datasource=github-releases depName=yannh/kubeconform
KUBECONFORM_VERSION := v0.6.7
# renovate: datasource=docker
PYTHON_IMAGE := docker.io/python:3.12-slim-bookworm
K8S_VERSION := master
HELM_VALUES_OVERRIDE := "helm_lint_values_override.yaml"

REPO_ROOT := $(shell git rev-parse --show-toplevel)
TETRAGON_CHART := tetragon
CRDS_RELATIVE_DIR := pkg/k8s/apis/cilium.io/client/crds/v1alpha1
CRDS := $(REPO_ROOT)/$(CRDS_RELATIVE_DIR)
JSON_SCHEMAS := $(REPO_ROOT)/install/kubernetes/schemas

HELM ?= docker run --rm -v $(CURDIR)/$(TETRAGON_CHART):/apps -v $(CURDIR)/$(HELM_VALUES_OVERRIDE):/$(HELM_VALUES_OVERRIDE) $(HELM_IMAGE)
PYTHON ?= docker run --rm -v $(REPO_ROOT):/code --workdir=/code/install/kubernetes -e FILENAME_FORMAT='{kind}-{fullgroup}' $(PYTHON_IMAGE)

.PHONY: all
all: $(TETRAGON_CHART)/crds-yaml lint docs openapi2jsonschema.py generate-jsonschemas kubeconform

.PHONY: lint
lint:
	$(HELM) lint . --with-subcharts

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

# openapi2jsonschema.py script generating JSON schema from the CRD YAML spec.
.PHONY: openapi2jsonschema.py
openapi2jsonschema.py:
	curl -sSfLO https://raw.githubusercontent.com/yannh/kubeconform/$(KUBECONFORM_VERSION)/scripts/$@

# To validate (using openapi2jsonschema.py) default Ruleset policies included in the Helm chart, we need to pass the
# JSON schema of the TracingPolicy CRD. This target generates such schema.
.PHONY: generate-jsonschemas
generate-jsonschemas: $(CRDS)
	mkdir -p $(JSON_SCHEMAS)/
	$(PYTHON) /bin/bash -c "pip install pyyaml && python /code/install/kubernetes/openapi2jsonschema.py /code/$(CRDS_RELATIVE_DIR)/*"
	mv $(REPO_ROOT)/install/kubernetes/*-cilium.io.json $(JSON_SCHEMAS)/

.PHONY: kubeconform
kubeconform:
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
	@echo ""
