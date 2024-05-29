---
title: "Submitting a pull request"
weight: 5
description: "Learn how to submit a pull request to the project"
---

{{< note >}}
This guide assumes that you have already made and tested changes you want to contribute. If you have not,
please follow the steps from the [Contribution Guide]({{< ref "/docs/contribution-guide#guide-for-code-and-docs-contribution" >}}).
{{< /note >}}

## Commit changes

Save your changes in one or more commits. Commits should separate logical chunks of code and not represent
a chronological list of changes. Ideally, each commit compiles and is functional on its own to allow for bisecting.

If in code review you are requested to make changes, squash the follow-up changes into the existing commits.
If you are not comfortable with Git yet (in particular with `git rebase`), refer to the [GitHub documentation](https://docs.github.com/en/get-started/using-git/using-git-rebase-on-the-command-line).

### Write a commit message

All commits must contain a well-written commit message:

1. Write a title, **no longer than 75 characters**. If the commit covers one specific area, start the title with
   a prefix like `helm:` or `metrics:`.
2. Describe the changes in the commit description. Focus on answering the question why the change is required and
   document anything that might be unexpected. If any explanation is required to understand your code, then it should
   be written in the code comments instead of the commit description.
3. Add a `Fixes: #XXX` line if the commit addresses a particular GitHub issue identified by its number. Note that the
   GitHub issue will be automatically closed when the commit is merged.
4. All commits **must be signed off** `(git commit -s)`.
   See the section [Developer's Certificate of Origin]({{< ref "/docs/contribution-guide/developer-certificate-of-origin" >}}).

### Example commit message

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

## Submit a pull request

Contributions must be submitted in the form of pull requests against the
upstream GitHub repository at https://github.com/cilium/tetragon.

Please follow the checklist in the pull request template and write anything that reviewers should be aware of in the
pull request description. After you create a pull request, a reviewer will be automatically assigned. They will provide
feedback, add relevant labels and run the CI workflows if needed.

## Frequently Asked Questions

### CI is complaining about Go module vendoring, what do I do?

You can run `make vendor` then add and commit your changes.

### CI is complaining about a missing "signed-off-by" line. What do I do?

You need to add a signed-off-by line to your commit messages. The easiest way
to do this is with `git fetch origin/main && git rebase --signoff origin/main`.
Then push your changes.
