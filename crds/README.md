# Custom Resource Definitions for Tetragon

Custom resource definition YAML files in this directory are auto-generated
using [controller-gen](https://book.kubebuilder.io/reference/controller-gen.html)
based on types defined in [pkg/k8s/apis/cilium.io](../pkg/k8s/apis/cilium.io).
Run:

    make generate

from the top-level directory to regenerated these files.

See [examples](examples) directory for example custom resources. These
examples are written manually. Add more examples if you feel like it.

# To Deploy sample write.yaml

$ kubectl apply -f ./cilium.io_tracingpolicies.yaml
$ kubectl apply -f ./examples/write.yaml
