---
title: "Verify Tetragon image signatures"
weight: 1
description: "Learn how to verify Tetragon container images signatures."
---

### Prerequisites

You will need to [install cosign](https://docs.sigstore.dev/cosign/installation/).

### Verify Signed Container Images

Since version 0.8.4, all Tetragon container images are signed using cosign.

Let's verify a Tetragon image's signature using the `cosign verify` command:

```shell
COSIGN_EXPERIMENTAL=1 cosign verify --certificate-github-workflow-repository cilium/tetragon --certificate-oidc-issuer https://token.actions.githubusercontent.com <Image URL> | jq
```

**Note**

`COSIGN_EXPERIMENTAL=1` is used to allow verification of images signed in
KEYLESS mode. To learn more about keyless signing, please refer to [Keyless
Signatures](https://github.com/sigstore/cosign/blob/main/KEYLESS.md#keyless-signatures).

