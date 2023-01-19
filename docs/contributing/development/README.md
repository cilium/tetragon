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

4. Clone your `${YOUR_GITHUB_USERNAME_OR_ORG}/tetragon` fork into your `GOPATH`, and set up the base repository as `upstream` remote:

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

7. Follow the steps in [Making Changes](#making-changes) to start contributing :)

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

6. All important steps in [Making Changes](#making-changes) have been followed.

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
  * go 1.18
  * GNU make
  * A running docker service
  * `libcap` and `libelf` (in Debian systems, e.g., install `libelf-dev` and
    `libcap-dev`)

You can build Tetragon as follows:

```
make
```

If you want to use `podman` instead of `docker`, you can do the following (assuming you
need to use `sudo` with `podman`):
```
CONTAINER_ENGINE='sudo podman' make
```
You can ignore `/bin/sh: docker: command not found` in the output.

To build using the local clang, you can use:
```
CONTAINER_ENGINE='sudo podman' LOCAL_CLANG=1 LOCAL_CLANG_FORMAT=1 make
```
See [Dockerfile.clang](https://github.com/cilium/tetragon/blob/main/Dockerfile.clang) for the minimal required version of `clang`.

You should now have a `./tetragon` binary, which can be run as follows:

```
sudo ./tetragon --bpf-lib bpf/objs
```

Notes:

1. The `--bpf-lib` flag tells Tetragon where to look for its compiled BPF programs
(which were built in the `make` step above).

2. If Tetragon fails with an error `"BTF discovery: candidate btf file does not exist"`, then make sure that your kernel support [BTF](#btf-requirement), otherwise place a BTF file where Tetragon can read it and specify its path with the `--btf` flag.

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

### Building and running a Docker image

The base kernel should support [BTF](../../../README.md#btf-requirement) or a BTF file should
be bind mounted on top of `/var/lib/tetragon/btf` inside container.

To build Tetragon image:
```
make image
```

To run the image:
```
docker run --name tetragon \
   --rm -it -d --pid=host \
   --cgroupns=host --privileged \
   -v /sys/kernel/btf/vmlinux:/var/lib/tetragon/btf \
   cilium/tetragon:latest \
   bash -c "/usr/bin/tetragon"
```

Run the `tetra` binary to get Tetragon events:
```
docker exec -it tetragon \
   bash -c "/usr/bin/tetra getevents -o compact"
```

### Building and running as a systemd service

To build Tetragon tarball:
```
make tarball
```

The produced tarball will be inside directory `./build/`, then follow the [Package deployment guide][package-deployment] to install it as a systemd service.

[package-deployment]: ../../deployment/package/README.md

### Running Tetragon in kind

The scripts in contrib/localdev will help you run Tetragon locally in a kind cluster.
First, ensure that docker, kind, kubectl, and helm are installed on your system.
Then, run the following commands:

```
# Build Tetragon agent and operator images
make LOCAL_CLANG=0 image image-operator

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

If you are getting an error, you can try to run `sudo launchctl load /Library/LaunchDaemons/org.virtualbox.startup.plist` (from https://stackoverflow.com/questions/18149546/macos-vagrant-up-failed-dev-vboxnetctl-no-such-file-or-directory).

### Making Changes

1. Make sure the main branch of your fork is up-to-date:

   ```
   git fetch upstream
   git checkout main
   git merge upstream/main
   ```

   For further reference read [github syncing a fork](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/working-with-forks/syncing-a-fork) documentation.

2. Create a PR branch with a descriptive name, branching from main:

   ```
   git switch -c pr/${GITHUB_USERNAME_OR_ORG}/changes-to-something main
   ```

3. Make the changes you want.

4. Separate the changes into logical commits.

   - Describe the changes in the commit messages. Focus on answering the question why the change is required and document anything that might be unexpected.
   - If any description is required to understand your code changes, then those instructions should be code comments instead of statements in the commit description.
   - For submitting PRs, all commits need to be signed off `(git commit -s)`. See the section [Developer's Certificate of Origin](#developers-certificate-of-origin)

5. Make sure your changes meet the following criteria:

   - New code is covered by Integration Testing.
   - End to end integration / runtime tests have been extended or added. If not required, mention in the commit message what existing test covers the new code.
   - Follow-up commits are squashed together nicely. Commits should separate logical chunks of code and not represent a chronological list of changes.

6. Run `git diff --check` to catch obvious white space violations

7. Build Tetragon with your changes included.

### Running Tests
See <https://github.com/cilium/tetragon/blob/main/tests/vmtests/README.md>.
