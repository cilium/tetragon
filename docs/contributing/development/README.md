# Development Guide

We're happy you're interested in contributing to the Tetragon project.

This section of the Tetragon documentation will help you make sure you
have an environment capable of testing changes to the Tetragon source code,
and that you understand the workflow of getting these changes reviewed and
merged upstream.

## How To Contribute

### Clone and Provision Environment

1. Make sure you have a [GitHub account](https://github.com/join)

2. Fork the Tetragon repository to your GitHub user or organization.

3. Turn off GitHub actions for your fork as described in the [GitHub
Docs](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository#managing-github-actions-permissions-for-your-repository>)
   - This is recommended to avoid unnecessary CI notification failures on the fork.

4. Clone your `${YOUR_GITHUB_USERNAME_OR_ORG}/tetragon` fork into your `GOPATH`, and setup the base repository as `upstream` remote:

```
   mkdir -p "${GOPATH}/src/github.com/cilium"
   cd "${GOPATH}/src/github.com/cilium"
   git clone https://github.com/${YOUR_GITHUB_USERNAME_OR_ORG}/tetragon.git
   cd tetragon
   git remote add upstream https://github.com/cilium/tetragon.git
```

5. Prepare your [Development Setup](#development-setup), see below.

6. Check the GitHub issues for [good tasks to get
started](https://github.com/cilium/tetragon/issues?q=is%3Aopen+is%3Aissue+label%3Agood-first-issue)

### Submitting a pull request

Contributions must be submitted in the form of pull requests against the upstream GitHub repository at https://github.com/cilium/tetragon.

1. Fork the Tetragon repository.

2. Push your changes to the topic branch in your fork of the repository.

3. Submit a pull request on https://github.com/cilium/tetragon.

Before hitting the submit button, please make sure that the following requirements have been met:

1. Each commit compiles and is functional on its own to allow for bisecting of commits.

2. All code is covered by unit and/or runtime tests where feasible.

3. All changes have been tested and checked for regressions by running the existing testsuite against your changes.

4. All commits contain a well written commit description including a title, description and a `Fixes: #XXX` line if the commit addresses a particular GitHub issue identified by its number. Note that the GitHub issue will be automatically closed when the commit is merged.

   ```
   doc: add contribution guideline and how to submit pull requests

   Tetragon Open Source project was just released and it does not include
   default contributing guidelines.

   This patch fixes this by adding:

   1. CONTRIBUTING.md file in the root directory as suggested by github documentation: https://docs.github.com/en/communities/setting-up-your-project-for-healthy-contributions/setting-guidelines-for-repository-contributors

   2. Development guide under docs directory with a section on how to submit pull requests. 

   3. Moves the DEVELOP.md file from root directory to the `docs/contributing/development/` one.

   Fixes: #33

   Signed-off-by: Djalal Harouni <djalal@cilium.io>
   ```

   Note: Make sure to include a blank line in between commit title and commit description.

5. All commits are signed off. See the section [Developer’s Certificate of Origin][dev-coo].

[dev-coo](#developers-certificate-of-origin)

### Developer’s Certificate of Origin

To improve tracking of who did what, we’ve introduced a “sign-off” procedure,
make sure to read and apply the 
[Developer’s Certificate of
Origin](https://docs.cilium.io/en/stable/contributing/development/contributing_guide/#developer-s-certificate-of-origin).


## Development Setup

The following sections will help you to get started with making
changes and building Tetragon.

### Building and Running Tetragon

For local development, you will likely want to build and run bare-metal Tetragon.

Requirements:
  * go 1.17
  * GNU make
  * A running docker service
  * `libcap` and `libelf` (in Debian systems, e.g., install `libelf-dev` and
    `libcap-dev`)

Tetragon relies on a permanent fork of libbpf and a fork of clang with some custom patches in order
to build and load its BPF programs correctly. We first need to get a local copy of both, which can be done
with:

```
make tools-install
```

After running the above command, you are ready to build Tetragon as follows:

```
LD_LIBRARY_PATH=$(realpath ./lib) make LOCAL_CLANG=0
```

You should now have a `./tetragon` binary, which can be run as follows:

```
sudo LD_LIBRARY_PATH=$(realpath ./lib) ./tetragon --bpf-lib bpf/objs
```

Note that we need to specify the `LD_LIBRARY_PATH` as shown above so that Tetragon can find
the correct libbpf to use at runtime. The `--bpf-lib` flag tells Tetragon where to look
for its compiled BPF programs (which were built in the `make` step above).

### Running Code Generation

Tetragon uses code generation based on protoc to generate large amounts of boilerplate
code based on our protobuf API. We similarly use automatic generation to maintain our k8s
CRDs. Whenever you make changes to these files, you will be required to re-run code generation
before your PR can be accepted.

To run codegen from protoc, run the following command from the root of the repository:
```
make codegen
```

And to run k8s CRD generation, run the following command from the root of the repository:
```
make generate
```

Finally, should you wish to modify any of the resulting codegen files (ending in .pb.go),
do not modify them directly. Instead, you can edit the files in
`cmd/protoc-gen-go-tetragon` and then re-run `make codegen`.

### Running Tetragon in kind

The scripts in contrib/localdev will help you run Tetragon locally in a kind cluster.
First, ensure that docker, kind, kubectl, and helm are installed on your system.
Then, run the following commands:

```
# Build Tetragon agent and operator images
LD_LIBRARY_PATH=$(realpath ./lib) make LOCAL_CLANG=0 image image-operator

# Bootstrap the cluster
contrib/localdev/bootstrap-kind-cluster.sh

# Install Tetragon
contrib/localdev/install-tetragon.sh --image cilium/tetragon:latest --operator cilium/tetragon-operator:latest
```

Verify that Tetragon is installed by running:
```
kubectl get pods -n kube-system
```

### Local Development in Vagrant Box

If you are on a Mac, use Vagrant to create a dev VM:

    vagrant up
    vagrant ssh
    make
