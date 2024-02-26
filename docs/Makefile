# retrieve the hugo version from the netlify config file
HUGO_VERSION      = $(shell grep ^HUGO_VERSION ../netlify.toml | tail -n 1 | cut -d '=' -f 2 | tr -d " \"\n")
CONTAINER_ENGINE ?= docker
CONTAINER_IMAGE  ?= cilium/tetragon-hugo:v$(HUGO_VERSION)
# mount the parent folder to get the git history for Docsy to display the "last modified" indicator
CONTAINER_RUN    ?= "$(CONTAINER_ENGINE)" run --rm --interactive --tty --workdir /src/docs
HUGO_DOCKERFILE  ?= Dockerfile.hugo

.PHONY: preview
preview: image
	$(CONTAINER_RUN) --cap-drop=ALL --cap-add=AUDIT_WRITE --read-only --mount type=tmpfs,destination=/tmp,tmpfs-mode=01777 -p 1313:1313 $(CONTAINER_IMAGE) server --buildFuture --environment development --bind 0.0.0.0 --destination /tmp/hugo --cleanDestinationDir --noBuildLock

.PHONY: image
image: ## Build a container image for the preview of the website;
	# run build in parent directory of Dockerfile in order to include
	# Tetragon CRDs (in pkg/k8s) in build context and to mount them
	# in Dockerfile.hugo
	cd .. && DOCKER_BUILDKIT=1 $(CONTAINER_ENGINE) build -f docs/${HUGO_DOCKERFILE} . --network host --tag $(CONTAINER_IMAGE) --build-arg HUGO_VERSION=$(HUGO_VERSION)

.PHONY: clean
clean:
	docker image rm $(CONTAINER_IMAGE)

