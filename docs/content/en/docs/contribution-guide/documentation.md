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


