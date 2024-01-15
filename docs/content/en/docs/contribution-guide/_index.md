---
title: "Contribution Guide"
weight: 8
description: >
  How to contribute to the project
---

Welcome to Tetragon :) !

We're happy you're interested in contributing to the Tetragon project.

This section of the Tetragon documentation will help you make sure you
have an environment capable of testing changes to the Tetragon source code,
and that you understand the workflow of getting these changes reviewed and
merged upstream.

## Clone and provision an environment

1. Make sure you have a [GitHub account](https://github.com/join).

2. [Fork the Tetragon repository](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/working-with-forks/fork-a-repo)
   to your GitHub user or organization. The repository is available under
   [github.com/cilium/tetragon](https://github.com/cilium/tetragon).

3. (Optional) [Turn off GitHub actions](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository#about-github-actions-permissions-for-your-repository)
   for your fork. This is recommended to avoid unnecessary CI notification
   failures on the fork.

4. [Clone your fork](https://docs.github.com/en/repositories/creating-and-managing-repositories/cloning-a-repository)
   and set up the base repository as `upstream` remote:

   ```shell
   git clone https://github.com/${YOUR_GITHUB_USERNAME_OR_ORG}/tetragon.git
   cd tetragon
   git remote add upstream https://github.com/cilium/tetragon.git
   ```

5. Prepare your [development setup]({{< ref "/docs/contribution-guide/development-setup" >}}).

6. Check out GitHub [good first issues](https://github.com/cilium/tetragon/issues?q=is%3Aopen+is%3Aissue+label%3A%22good+first+issue%22)
   to find something to work on. If this is your first Tetragon issue, try to
   start with something small that you think you can do without too much
   external help. Also avoid assigning too many issues to yourself (see [Don't
   Lick the Cookie!](https://www.redhat.com/en/blog/dont-lick-cookie)).

7. Follow the steps in [making changes]({{< ref "/docs/contribution-guide/making-changes" >}})
   to start contributing.

8. Learn how to [run the tests]({{< ref "/docs/contribution-guide/running-tests" >}}).

9. Learn how to [submit a pull request]({{< ref "/docs/contribution-guide/submitting-a-pull-request" >}})
   to the project.

10. Please accept our gratitude for taking the time to improve Tetragon! :)
