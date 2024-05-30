---
title: "Release & upgrade notes"
weight: 7
description: "Guide on how to write release notes for new contributions."
---

Tetragon release notes are published on the [GitHub releases page](https://github.com/cilium/tetragon/releases).
To ensure the release notes are accurate and helpful, contributors should write them alongside development. Then, at
the time of release, the final notes are compiled and published.

This guide is intended for both Tetragon developers and reviewers. Please follow it when creating or reviewing pull
requests.

## `release-note` blurb in PR

When you create a pull request, the template will include a `release-note` blurb in the description. Write a short
description of your change there. Focus on the user perspective - that is, what functionality is available, not how
it's implemented.

The `release-note` blurb will be compiled into the release notes as a bullet point. If you delete the `release-note`
blurb from the PR description, then the PR title will be used instead (it's reasonable to do so for example when the
change has no user impact).

## `release-note/*` label

Each pull request should have exactly one `release-note/*` label. The label will be added by a reviewer, but feel free
to suggest one when you create a PR.

The following `release-note/*` labels are available:

* `release-note/major` - use it for changes you want to be highlighted in the release. Typically these are new
  features, but the question to answer is always if it's a highlight of the release, not how big or new the change is.
* `release-note/minor` - use it for other user-visible changes, for example improving an existing functionality or
  adding a new config option
* `release-note/bug` - use it for bug fixes
* `release-note/misc` - use it for changes that don't have any user impact, for example refactoring or tests
* `release-note/ci` - use it for CI-only changes (`.github` directory)
* `release-note/docs` - use it for documentation-only changes (`docs` directory)
* `release-note/dependency` - use it for PRs that only update dependencies. This label is added automatically to PRs
  created by Renovate bot and is rarely used by humans.

## Upgrade notes

Upgrade notes highlight changes that require attention when upgrading Tetragon. They instruct users on how to adapt in
case the change requires a manual intervention.

Examples of changes that should be covered in upgrade notes:
* renaming/removing config options
* renaming/removing API fields
* renaming/removing metrics or metric labels
* changes with a significant performance impact
* deprecations

If your change entails an upgrade note, write it in the `contrib/upgrade-notes/latest.md` file (if your change doesn't
fit nicely in the predefined sections, just add a note at the top). The upgrade notes will be included in the release,
in addition to the regular release notes.
