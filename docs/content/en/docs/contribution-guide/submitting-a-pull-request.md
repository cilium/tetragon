---
title: "Submitting a pull request"
weight: 4
description: "Learn how to submit a pull request to the project"
---

### Submitting a pull request

Contributions must be submitted in the form of pull requests against the
upstream GitHub repository at https://github.com/cilium/tetragon.

1. Fork the Tetragon repository.

2. Push your changes to the topic branch in your fork of the repository.

3. Submit a pull request on https://github.com/cilium/tetragon.

Before hitting the submit button, please make sure that the following
requirements have been met:

1. Each commit compiles and is functional on its own to allow for bisecting of
   commits.

2. All code is covered by unit and/or runtime tests where feasible.

3. All changes have been tested and checked for regressions by running the
   existing testsuite against your changes.

4. All commits contain a well written commit description including a title,
   description and a `Fixes: #XXX` line if the commit addresses a particular
   GitHub issue identified by its number. Note that the GitHub issue will be
   automatically closed when the commit is merged.

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

5. All commits are signed off. See the section [Developer’s Certificate of
   Origin](/docs/contribution-guide/developer-certificate-of-origin/).

6. All important steps in [Making changes](/docs/contribution-guide/making-changes/) have been followed.

