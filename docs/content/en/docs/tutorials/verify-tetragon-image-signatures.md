---
title: "Verify installation"
weight: 5
description: "Verify Tetragon image and software bill of materials signatures"
aliases: ["/docs/tutorials/verify-tetragon-image-signatures", "/docs/tutorials/software-bill-of-materials"]
---

## Verify Tetragon image signature

Learn how to verify Tetragon container images signatures.

### Prerequisites

You will need to [install cosign](https://docs.sigstore.dev/system_config/installation/).

### Verify Signed Container Images

Since version 0.8.4, all Tetragon container images are signed using cosign.

Let's verify a Tetragon image's signature using the `cosign verify` command:

```shell
cosign verify --certificate-github-workflow-repository cilium/tetragon --certificate-oidc-issuer https://token.actions.githubusercontent.com <Image URL> | jq
```

{{< note >}}
If you are using cosign < v2.0.0, you must set `COSIGN_EXPERIMENTAL=1`
environment variable to allow verification of images signed in KEYLESS mode.
To learn more about keyless signing, please refer to [Sigstore documentation](https://docs.sigstore.dev/signing/overview/).
{{< /note >}}

## Verify the SBOM signature

Download and verify the signature of the software bill of materials

A Software Bill of Materials (SBOM) is a complete, formally structured list of
components that are required to build a given piece of software. SBOM provides
insight into the software supply chain and any potential concerns related to
license compliance and security that might exist.

Starting with version 0.8.4, all Tetragon images include an SBOM. The SBOM is
generated in [SPDX](https://spdx.dev/) format using the
[bom](https://github.com/kubernetes-sigs/bom) tool. If you are new to the
concept of SBOM, see [what an SBOM can do for you](https://www.chainguard.dev/unchained/what-an-sbom-can-do-for-you).

### Download SBOM

The SBOM can be downloaded from the supplied Tetragon image using the `cosign
download sbom` command.

```shell
cosign download sbom --output-file sbom.spdx <Image URL>
```

### Verify SBOM Image Signature

To ensure the SBOM is tamper-proof, its signature can be verified using the
`cosign verify` command.

```shell
COSIGN_EXPERIMENTAL=1 cosign verify --certificate-github-workflow-repository cilium/tetragon --certificate-oidc-issuer https://token.actions.githubusercontent.com --attachment sbom <Image URL> | jq
```

It can be validated that the SBOM image was signed using Github Actions in the
Cilium repository from the `Issuer` and `Subject` fields of the output.
