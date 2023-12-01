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
   [github syncing a fork](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/working-with-forks/syncing-a-fork)
   documentation.

2. Create a PR branch with a descriptive name, branching from main:

   ```shell
   git switch -c pr/${GITHUB_USERNAME_OR_ORG}/changes-to-something main
   ```

3. Make the changes you want.

4. Separate the changes into logical commits.

   - Describe the changes in the commit messages. Focus on answering the
     question why the change is required and document anything that might be
     unexpected.
   - If any description is required to understand your code changes, then those
     instructions should be code comments instead of statements in the commit
     description.
   - For submitting PRs, all commits need to be signed off `(git commit -s)`.
     See the section [Developer's Certificate of Origin](/docs/contribution-guide/developer-certificate-of-origin/)

5. Make sure your changes meet the following criteria:

   - New code is covered by Integration Testing.
   - End to end integration / runtime tests have been extended or added. If not
     required, mention in the commit message what existing test covers the new
     code.
   - Follow-up commits are squashed together nicely. Commits should separate
     logical chunks of code and not represent a chronological list of changes.

6. Run `git diff --check` to catch obvious white space violations

7. Build Tetragon with your changes included.

### What's next

- See how to [run the tests of the project](/docs/contribution-guide/running-tests/).
- See how to [submit your first pull request](/docs/contribution-guide/submitting-a-pull-request/).

