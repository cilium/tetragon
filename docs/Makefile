# retrieve the hugo version from the netlify config file
HUGO_VERSION      = $(shell grep ^HUGO_VERSION ../netlify.toml | tail -n 1 | cut -d '=' -f 2 | tr -d " \"\n")
CONTAINER_ENGINE ?= docker
CONTAINER_IMAGE  ?= cilium/tetragon-hugo:v$(HUGO_VERSION)
CONTAINER_FLAGS ?= --interactive --tty
BASE_URL        ?= /
# Mount site inputs individually as read-only
DOCS_INPUTS      := $(wildcard archetypes assets config content data i18n layouts static)
DOCS_MOUNTS      = $(foreach path,$(DOCS_INPUTS),--volume "$(CURDIR)/$(path):/src/docs/$(path):ro")
# Git history lets Docsy display the "last modified" indicator.
CONTAINER_RUN    ?= "$(CONTAINER_ENGINE)" run --rm $(CONTAINER_FLAGS) $(DOCS_MOUNTS) --volume "$(abspath $(CURDIR)/..)/.git:/src/.git:ro" --workdir /src/docs
HUGO_DOCKERFILE  ?= Dockerfile.hugo

# Tracing Policy docs generation settings
TRACING_POLICY_TEMPLATE := content/en/docs/reference/templates/tracing_policy.tmpl
TRACING_POLICY_OUTPUT := content/en/docs/reference/tracing-policy.md
TRACING_POLICY_CRDS_DIR := ../pkg/k8s/apis/cilium.io/client/crds/v1alpha1

# Path to crdoc binary (can be overridden by environment)
# See https://github.com/fybrik/crdoc
CRDOC ?= docker run --rm --platform linux/amd64 -u $(shell id -u):$(shell id -g) \
	-v $(abspath $(CURDIR)/$(TRACING_POLICY_CRDS_DIR)):/crds \
	-v $(abspath $(CURDIR)):/workdir ghcr.io/fybrik/crdoc:0.6.2

.PHONY: preview
preview: image
	$(CONTAINER_RUN) --cap-drop=ALL --cap-add=AUDIT_WRITE --read-only --mount type=tmpfs,destination=/tmp,tmpfs-mode=01777 -p 1313:1313 $(CONTAINER_IMAGE) server --buildFuture --environment development --bind 0.0.0.0 --destination /tmp/hugo --cleanDestinationDir --noBuildLock

.PHONY: image
image: ## Build a container image for the preview of the website
	DOCKER_BUILDKIT=1 $(CONTAINER_ENGINE) build -f ${HUGO_DOCKERFILE} . --network host --tag $(CONTAINER_IMAGE) --build-arg HUGO_VERSION=$(HUGO_VERSION)

.PHONY: build
build: CONTAINER_FLAGS =
build: image ## Build the production website into public without a terminal.
	mkdir -p public
	$(CONTAINER_RUN) --read-only --mount type=tmpfs,destination=/tmp,tmpfs-mode=01777 --user "$(shell id -u):$(shell id -g)" --env HOME=/home/hugo --volume "$(CURDIR)/public:/src/docs/public" $(CONTAINER_IMAGE) --minify --environment production --baseURL "$(BASE_URL)" --cacheDir /tmp/hugo-cache --noBuildLock

.PHONY: clean
clean:
	docker image rm $(CONTAINER_IMAGE)

.PHONY: tracing-policy-docs
tracing-policy-docs: ## Generate Tracing Policy reference page from CRDs.
	$(CRDOC) --resources /crds \
		--output /workdir/$(TRACING_POLICY_OUTPUT) \
		--template /workdir/$(TRACING_POLICY_TEMPLATE)
