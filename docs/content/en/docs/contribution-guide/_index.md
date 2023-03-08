---
title: "Contribution Guide"
linkTitle: "Contribution Guide"
weight: 6
description: >
  How to contribute to the project
---

We're happy you're interested in contributing to the Tetragon project.

This section of the Tetragon documentation will help you make sure you
have an environment capable of testing changes to the Tetragon source code,
and that you understand the workflow of getting these changes reviewed and
merged upstream.

### Clone and provision an environment

1. Make sure you have a [GitHub account](https://github.com/join).

2. Fork the Tetragon repository to your GitHub user or organization.

3. Turn off GitHub actions for your fork as described in the
   [GitHub Docs](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository#managing-github-actions-permissions-for-your-repository>).

   This is recommended to avoid unnecessary CI notification failures on the fork.

4. Clone your `${YOUR_GITHUB_USERNAME_OR_ORG}/tetragon` fork into your
   `GOPATH`, and set up the base repository as `upstream` remote:

   ```shell
   mkdir -p "${GOPATH}/src/github.com/cilium"
   cd "${GOPATH}/src/github.com/cilium"
   git clone https://github.com/${YOUR_GITHUB_USERNAME_OR_ORG}/tetragon.git
   cd tetragon
   git remote add upstream https://github.com/cilium/tetragon.git
   ```

5. Prepare your [Development setup](/docs/contribution-guide/development-setup),
   see section below.

6. Check the GitHub issues for [good tasks to get
   started](https://github.com/cilium/tetragon/issues?q=is%3Aopen+is%3Aissue+label%3A%22good+first+issue%22).

7. Follow the steps in [Making changes](/docs/contribution-guide/making-changes) to start contributing. Welcome :)!

