---
title: "FAQ"
weight: 7
description: "List of frequently asked questions"
---

**Q:** Can I install and use Tetragon in standalone mode (outside of k8s)?

**A:** Yes! You can run `make` to generate standalone binaries and run them directly.
Make sure to take a look at the [Development Setup](docs/contributing/development/README.md#development-setup)
guide for the build requirements. Then use `sudo ./tetragon --bpf-lib bpf/objs`
to run Tetragon.

----

**Q:** CI is complaining about Go module vendoring, what do I do?

**A:** You can run `make vendor` then add and commit your changes.

----

**Q:** CI is complaining about a missing "signed-off-by" line. What do I do?

**A:** You need to add a signed-off-by line to your commit messages. The easiest way to do
this is with `git fetch origin/main && git rebase --signoff origin/main`. Then push your changes.


