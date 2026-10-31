<!-- Copyright (C) Isovalent, Inc. - All Rights Reserved. -->

# TracingPolicy CEL Cost Report

Run from the repository root:

```bash
make cel-cost
```

The target runs the existing `crds` target to regenerate CRDs from the current
Go validation markers, then recreates
[results/tracingpolicy-cel-costs.md](../../results/tracingpolicy-cel-costs.md).
The tool reads generated CRDs, not validation comments directly.

The Markdown contains a Mermaid overview, Go structs with per-field subtree
costs, a cost-bearing schema tree, and every rule's raw cost and cardinality
multiplier. It includes a source fingerprint and the Kubernetes library version.

Options:

```bash
go run -mod=vendor ./tools/cel-cost/main.go -help
go run -mod=vendor ./tools/cel-cost/main.go \
  -crd pkg/k8s/apis/cilium.io/client/crds/v1alpha1/cilium.io_tracingpoliciesnamespaced.yaml \
  -version v1alpha1 \
  -output results/tracingpolicy-namespaced-cel-costs.md
```

Estimates use the vendored Kubernetes CEL compiler and its static CRD cost
aggregation: bounded ancestor cardinalities are multiplied; unbounded chains
use the compiler's request-size-based fallback. The schema-wide static budget
is 100,000,000 cost units. These are estimates, not runtime measurements or a
replacement for API-server validation, including its per-expression limit.
Parent totals include their descendants and must not be added to them again.
The report is tailored to this repository's TracingPolicy Go types and fails
if a cost-bearing rule cannot be mapped to an annotated struct.

Tests:

```bash
go test -mod=vendor ./tools/cel-cost/main.go
```