# Tetragon documentation

## Preview locally

### Using Docker

Install Docker locally, and then use:

```shell
make
```

Note that you can use `make docs` from the main Makefile at the root folder
level.

To cleanup, you can remove the built image using:

```shell
make clean
```

### Local Hugo installation

The documentation is a [Hugo static website](https://github.com/gohugoio/hugo)
using the [Docsy theme](https://github.com/google/docsy).

Please refer to both dedicated guides on how to install Hugo+extended and how
to tweak Docsy but generally, to preview your work:
```shell
hugo server
```

## Content

Shortcut to the content:
[content/en/docs](https://github.com/cilium/tetragon/tree/main/docs/content/en/docs).

## Style

We generally follow the Kuberentes docs style guide: https://kubernetes.io/docs/contribute/style/style-guide/
