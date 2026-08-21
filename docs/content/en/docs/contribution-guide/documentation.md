---
title: "Documentation"
weight: 4
description: "Learn how to contribute to the documentation"
---

Thank you for taking the time to improve Tetragon's documentation.

## Find the content

All the Tetragon documentation content can be found under
[github.com/cilium/tetragon/docs/content/en/docs](https://github.com/cilium/tetragon/tree/main/docs/content/en/docs).

{{< note >}}
The main page served from a directory path is named `_index.md`. For example
[/docs/contribution-guide]({{< ref "/docs/contribution-guide" >}}) is available
under [/docs/content/en/docs/contribution-guide/\_index.md](https://github.com/cilium/tetragon/blob/main/docs/content/en/docs/contribution-guide/_index.md).
{{< /note >}}

## Style to follow

We generally follow the Kubernetes docs style guide
[k8s.io/docs/contribute/style/style-guide](https://kubernetes.io/docs/contribute/style/style-guide/).

## Reference a policy from the policy collection

[`policies/`](https://github.com/cilium/tetragon/tree/main/policies), at the
root of the repository, is the single, central place where every example
`TracingPolicy` referenced from the docs lives, organized into subfolders by
use case (`network-monitoring`, `file-monitoring`, `process-credentials`,
`process-monitoring`, `system-integrity`, `cves`, `others`). Keeping policies
here instead of scattered across doc pages means each policy exists exactly
once, is easy to find, and is easy to reference from anywhere in the docs.

### Adding a new policy to the docs

If you're writing or updating a doc page and need a policy that doesn't exist
in the library yet, follow this two-step process:

1. **Add the policy file to `policies/`**, in the subfolder that matches the
   policy's primary use case. For example, a policy about monitoring network
   connections goes in `policies/network-monitoring/`; a policy about kernel
   modules goes in `policies/system-integrity/`. If none of the existing
   subfolders fit, it's fine to to put it the `others` subfolder.
2. **Reference it from your doc page using a `policy-*` shortcode** (see
   below) instead of hand-typing a link, a `raw.githubusercontent.com` URL, or
   pasting the YAML content directly into the page.

**N/B**: the docs never duplicate a policy's content or link to it by a
hardcoded URL, and the docs build will fail loudly if the path is ever wrong.

If you mistype the path or forget to add the file, `hugo`/`make docs` stops
the build with an error naming the exact path it couldn't find, for example:
`policy-ref: policies/<category>/<file>.yaml not found`.

### Available shortcodes

In all three shortcodes below, the argument is the path relative to
`policies/`. Each entry shows the shortcode as you'd write it in a doc page,
followed by what it actually looks like once rendered.

`{{</* policy-ref "process-monitoring/uprobe.yaml" */>}}`
: Renders a link to the file on GitHub. Use this for prose like "Apply the
  `{{</* policy-ref "..." */>}}` policy". In practice it renders as:

  {{< policy-ref "process-monitoring/uprobe.yaml" >}}

`{{</* policy-raw-url "process-monitoring/uprobe.yaml" */>}}`
: Prints the bare `raw.githubusercontent.com` URL for the file. Use this
  inside shell commands, for example `kubectl apply -f {{</* policy-raw-url "..." */>}}`.
  In practice it renders as:

  {{< policy-raw-url "process-monitoring/uprobe.yaml" >}}

`{{</* policy-example "process-monitoring/uprobe.yaml" */>}}`
: Renders the file's content inline as a highlighted YAML code block, followed
  by a link to view it on GitHub. Use this when the page should show the
  policy itself rather than just link to it. In practice it renders as:

  {{< policy-example "process-monitoring/uprobe.yaml" >}}

## Preview locally

To preview the documentation locally, use one of the method below. Then browse
to [localhost:1313/docs](http://localhost:1313/docs), the default port used by Hugo to
listen.

{{< note >}}
When submitting a docs related pull request, a Netlify job will automatically
build a preview of your changes and post the link in a PR comment, it is often
a good idea to edit your initial PR message and link to the precise location
of your changes within the preview to help the reviewer's job.
{{< /note >}}

### Using Docker

With a Docker service available, from the root of the repository, use:

```shell
make docs
```

You can also use `make` from the Makefile at the `/docs` folder level.

To cleanup the container image built in the process, you can use:

```shell
make -C docs clean
```

### Local Hugo installation

The documentation is a [Hugo static website](https://github.com/gohugoio/hugo)
using the [Docsy theme](https://github.com/google/docsy).

Please refer to dedicated guides on how to install Hugo+extended and how to
tweak Docsy, but generally, to preview your work, from the `/docs` folder:
```shell
hugo server
```


