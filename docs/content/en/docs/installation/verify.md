---
title: "Verify installation"
weight: 5
description: "Verify Tetragon image and software bill of materials signatures"
aliases: ["/docs/tutorials/verify-tetragon-image-signatures", "/docs/tutorials/software-bill-of-materials"]
---

## Verify Tetragon image signature

Learn how to verify Tetragon container images signatures.

### Prerequisites

You will need to [install cosign](https://docs.sigstore.dev/cosign/system_config/installation/).

### Verify Signed Container Images

Since version 0.8.4, all Tetragon container images are signed using cosign.

Let's verify a Tetragon image's signature using the `cosign verify` command:

```shell
cosign verify \
  --certificate-github-workflow-repository cilium/tetragon \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp 'https://github\.com/cilium/tetragon/\.github/workflows/.+' \
  <Image URL> | jq
```

{{< note >}}
If you are using cosign < v2.0.0, you must set `COSIGN_EXPERIMENTAL=1`
environment variable to allow verification of images signed in KEYLESS mode.
To learn more about keyless signing, please refer to [Sigstore documentation](https://docs.sigstore.dev/cosign/signing/overview/).
{{< /note >}}

## Verify the SBOM signature

Download and verify the signature of the software bill of materials

A Software Bill of Materials (SBOM) is a complete, formally structured list of
components that are required to build a given piece of software. SBOM provides
insight into the software supply chain and any potential concerns related to
license compliance and security that might exist.

Starting with version 0.8.4, all Tetragon images include an SBOM. The SBOM is
generated in [SPDX JSON](https://spdx.dev/) format and published as a cosign
[attestation](https://docs.sigstore.dev/cosign/verifying/attestation/)
alongside the image. If you are new to the concept of SBOM, see
[what an SBOM can do for you](https://www.chainguard.dev/unchained/what-an-sbom-can-do-for-you).

{{< note >}}
**Upgrade note:** Releases prior to v1.8 published the SBOM as a separate
`.sbom` artifact attached with `cosign attach sbom`. Starting with v1.8, the
SBOM is published as an SPDX JSON attestation via `cosign attest --type
spdxjson`. The legacy commands below no longer apply to images built from v1.8
onward; use the attestation-based commands instead.

```shell
# Legacy (pre-v1.8) — no longer applicable
cosign download sbom <Image URL>
cosign verify --attachment sbom <Image URL>
```
{{< /note >}}

### Download SBOM

The SBOM can be extracted from the attestation using `cosign download
attestation` and decoding the base64-encoded payload:

```shell
cosign download attestation --predicate-type=https://spdx.dev/Document <Image URL> \
  | jq -r .dsseEnvelope.payload | base64 -d | jq .predicate > sbom.spdx.json
```

### Verify SBOM Attestation

To ensure the SBOM is tamper-proof, its attestation can be verified using the
`cosign verify-attestation` command.

```shell
cosign verify-attestation --type spdxjson \
  --certificate-github-workflow-repository cilium/tetragon \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp 'https://github\.com/cilium/tetragon/\.github/workflows/.+' \
  <Image URL> | jq
```

It can be validated that the SBOM attestation was signed using GitHub Actions
in the Cilium repository from the `Issuer` and `Subject` fields of the output.
