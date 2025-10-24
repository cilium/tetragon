---
title: "Submitting a pull request"
weight: 5
description: "Learn how to submit a pull request to the project"
---

{{< note >}}
This guide is partially based on the
[Cilium contributing guide](https://docs.cilium.io/en/latest/contributing/development/contributing_guide/#submitting-a-pull-request).
{{< /note >}}

{{< caution >}}
This guide assumes that you have already made and tested changes you want to contribute. If you have not,
please follow the steps from the [Contribution Guide]({{< ref "/docs/contribution-guide#guide-for-code-and-docs-contribution" >}}).
{{< /caution >}}

## Commit changes

Save your changes in one or more commits.  If you are not comfortable
with Git yet (in particular with `git rebase`), refer to the
[GitHub documentation](https://docs.github.com/en/get-started/using-git/using-git-rebase-on-the-command-line).

{{< caution >}}
Commits should separate logical chunks of code and not represent a
chronological list of changes. Each commit should compiles and is
functional on its own to allow for bisecting.

If in code review you are requested to make changes, squash the
follow-up changes into the existing commits.
{{< /caution >}}


### Write a commit message

All commits must contain a well-written commit message:

1. **Write a title, no longer than 72 characters**. The title should ideally
   answer the question "what?". If the commit covers one specific area, start
   the title with a prefix like `helm:`, `bpf:`, `pkg/sensors:`, or `metrics:`.
2. **Describe the changes in the commit description**. Focus on answering the
   question why the change is required and document anything that might be
   unexpected. If any explanation is required to understand your code, then it
   should be written in the code comments instead of the commit description.
   Please **wrap your commit description to ~70/80 chars** width lines (use
   `gq` in vim for example).
3. Add a `Fixes: #XXX` line if the commit addresses a particular GitHub issue
   identified by its number. Note that the GitHub issue will be automatically
   closed when the commit is merged.
4. If any of the commits fixes a particular commit already in the tree,
   that commit is referenced in the commit message of the bugfix.  The
   proper format for the `Fixes:` tag referring to commits is to use the
   first 12 characters of the git SHA followed by the full commit title as
   seen above without breaking the line.
   ```
   Fixes: 29b76c402b68 ("Refactor CRD defaulting and validation as generic")
   ```

4. All commits **must be signed off** `(git commit -s)`.
   See the section [Developer's Certificate of Origin]({{< ref "/docs/contribution-guide/developer-certificate-of-origin" >}}).

### Example commit messages

```
tetragon: Fix struct perf_event_info_type layout

We have a hole in perf_event_info_type which results in wrong number in
its go counterpart MsgGenericKprobePerfEvent which is aligned differently.

Make sure the C object does not have any holes.

Fixes: #4119
Signed-off-by: Jiri Olsa <jolsa@kernel.org>
```

Commit can contain previous output of commands, and the result after the patch
to explicit the benefit to the reviewer, it can also be logs output, benchmark
results, etc.

```
cmd/tetra: use text/tabwriter to format tp list output

Also add the support of load error by reusing the metric state recap.

Previously, the output of `tetra tp list` was a bit chaotic, for
example, with 2 policies, with one with a loading error, it looked like
the following:

    [1] invalid enabled:false filterID:0 namespace:(global) sensors:
        loadError: "policy handler 'tracing' failed loading policy 'invalid': tracing [...]
    [2] block-binary enabled:true filterID:0 namespace:(global) sensors:gkp-sensor-1

Now, using text/tabwriter, we redact the errors (use -o json for full
output) and put everything in columns:

    ID   NAME           STATE        FILTERID   NAMESPACE   SENSORS
    1    invalid        load_error   0          (global)
    2    block-binary   enabled      0          (global)    gkp-sensor-1

Signed-off-by: Mahe Tardy <mahe.tardy@gmail.com>
```

Commit message can contain the `Reported-by`, `Suggested-by`, etc., tags from
[the kernel documentation](https://www.kernel.org/doc/html/v6.17/process/submitting-patches.html#using-reported-by-tested-by-reviewed-by-suggested-by-and-fixes).
You can also use the [`Co-authored-by` tag](https://docs.github.com/en/pull-requests/committing-changes-to-your-project/creating-and-editing-commits/creating-a-commit-with-multiple-authors)
to create commits with multiple authors.

```
bpf: fix tail call program types for usdt sensor

As reported by Mahe newest kernels check properly on programs using
(some) maps being same type[^1]. We violate that with usdt tail called
programs having just 'uprobe' type.

[^1]: 4540aed51b12 ("bpf: Enforce expected_attach_type for tailcall compatibility")

Reported-by: Mahe Tardy <mahe.tardy@gmail.com>
Signed-off-by: Jiri Olsa <jolsa@kernel.org>
```

Include a `Fixes:` tag and try to explain a bug you found out.

```
pkg/crdutils: fix standalone custom resources validation

This fixes commit 29b76c4 ("Refactor CRD defaulting and validation
as generic") that was enhancing commit a9c9a0b ("pkg/tracingpolicy:
add k8s validation for meta and spec").

I think it's a typo that was introduced because when we do the validation
of the object, we give the function two versions of that object, cr that
is typed and was created by yaml.UnmarshalStrict the JSON object with
K8s default, and unstr that is the unstructured object version of what
was passed as input, but with K8s default. We need these two objects to
do the validation respectively on the ObjectMeta and the Spec.

When Unmarshaling the JSON object to the GenericTracingPolicy (or
others) types, all fields are set to their Golang defaults (!) in
addition to the K8s default that were already applied. So some missing
fields, that were defaulted by the K8s default were injected in the
process and thus only partial validation was done.

Fixes: 29b76c402b68 ("Refactor CRD defaulting and validation as generic")

Signed-off-by: Mahe Tardy <mahe.tardy@gmail.com>
```

## Submit a pull request

Contributions must be submitted in the form of pull requests against the
upstream GitHub repository at https://github.com/cilium/tetragon.

Please follow the checklist in the pull request template and write anything that reviewers should be aware of in the
pull request description. After you create a pull request, a reviewer will be automatically assigned. They will provide
feedback, add relevant labels and run the CI workflows if needed.

### Changelog and breaking changes

1. **Document any user-facing or breaking changes** in `contrib/upgrade-notes/latest.md`.
2. **Verify the release note text.** If not explicitly changed, the title of the PR
   will be used for the release notes. If you want to change this, you can add
   a special section to the description of the PR. These release notes are
   primarily going to be read by users, so it is important that release notes
   for bugs, major and minor features do not contain internal details of Cilium
   functionality which sometimes are irrelevant for users.

   Example of a bad release note
   ````
   ```release-note
   Fix concurrent access in k8s watchers structures
   ```
   ````

   Example of a good release note
   ````
   ```release-note
   Fix panic when Tetragon received an invalid Tracing Policy from Kubernetes
   ```
   ````

   {{< note >}}
   If multiple lines are provided, the PR title will be used and the lines will
   be added as sub items.
   {{< /note >}}
3. If you have permissions to do so, **pick the right release-note label**.
   These labels will be used to generate the release notes which will primarily
   be read by users.

   | Labels             | When to set                                                                                           |
   |--------------------|-------------------------------------------------------------------------------------------------------|
   | release-note/bug   | This is a non-trivial bugfix and is a user-facing bug                                                 |
   | release-note/major | This is a major feature addition, e.g. Add MongoDB support                                            |
   | release-note/minor | This is a minor feature addition, e.g. Add support for a Kubernetes version                           |
   | release-note/misc  | This is a not user-facing change, e.g. Refactor endpoint package, a bug fix of a non-released feature |
   | release-note/docs  | This is a documentation change.                                                                       |
   | release-note/ci    | This is a CI feature or bug fix.                                                                      |

## Frequently Asked Questions

### CI is complaining about Go module vendoring, what do I do?

You can run `make vendor` then add and commit your changes.

### CI is complaining about a missing "signed-off-by" line. What do I do?

You need to add a signed-off-by line to your commit messages. The easiest way
to do this is with `git fetch origin/main && git rebase --signoff origin/main`.
Then push your changes.
