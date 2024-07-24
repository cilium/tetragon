---
title: "Making changes"
weight: 2
description: "Learn how to make your first changes to the project"
---

1. Make sure the main branch of your fork is up-to-date:

   ```shell
   git fetch upstream
   git checkout main
   git merge upstream/main
   ```

   For further reference read
   [GitHub syncing a fork](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/working-with-forks/syncing-a-fork)
   documentation.

2. Create a PR branch with a descriptive name, branching from main:

   ```shell
   git switch -c pr/${GITHUB_USERNAME_OR_ORG}/changes-to-something main
   ```

3. Make the changes you want.

4. Test your changes. Follow [Development setup](/docs/contribution-guide/development-setup) and
   [Running tests](/docs/contribution-guide/running-tests) guides to build and test Tetragon.

   - Make sure that all new code is covered by unit and/or end-to-end tests where feasible.
   - Run Tetragon locally to validate everything works as expected.
   - If adding/extending tests is not required, mention in the commit message what existing test covers the new code
     or how you validated the change.

5. Run code/docs generation commands if needed (see the sections below for specific code areas).

6. Run `git diff --check` to catch obvious white space violations.

7. Follow [Submitting a pull request](/docs/contribution-guide/submitting-a-pull-request) guide to commit your changes
   and open a pull request.

## Making changes to documentation

To improve Tetragon documentation ([https://tetragon.io/](https://tetragon.io/)), please follow the
[documentation contribution guide](/docs/contribution-guide/documentation).

## Adding dependencies

Tetragon vendors Go dependencies. If you add a new Go dependency (`go.mod`), run:

```shell
make vendor
```

Most dependencies are updated automatically using Renovate. If this is not the desired behavior, you will need to
update the Renovate configuration (`.github/renovate.json5`).

## Making changes to protobuf API

Tetragon contains a protobuf API and uses code generation based on protoc to generate large amounts of boilerplate
code. Whenever you make changes to these files (`api/`) you need to run code generation:

```shell
make protogen
```

Should you wish to modify any of the resulting codegen files (ending in `.pb.go`), do not modify them directly.
Instead, you can edit the files in `tools/protoc-gen-go-tetragon/` and then re-run `make protogen`.

## Making changes to CRDs

Kubernetes Custom Resource Definitions (CRDs) are defined using Kubebuilder framework and shipped with generated Go
client and helpers code. They are also included in the Helm chart for easy installation. Whenever you make changes to
these files (`pkg/k8s/`), you need to run code generation:

```shell
make crds
```

## Making changes to Helm chart

If you make changes to the Helm values (`install/kubernetes/tetragon/values.yaml`), you need to update the generated
Helm values reference:

```shell
make -C install/kubernetes docs
```

## Making changes to Prometheus metrics

If you add, change or delete metrics, you need to update the generated metrics reference:

```shell
make metrics-docs
```

## What's next

- See how to [run the tests of the project](/docs/contribution-guide/running-tests/).
- See how to [submit your first pull request](/docs/contribution-guide/submitting-a-pull-request/).
