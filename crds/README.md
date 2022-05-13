# Custom Resource Definitions for FGS

Custom resource definition YAML files in this directory are auto-generated
using [controller-gen](https://book.kubebuilder.io/reference/controller-gen.html)
based on types defined in [pkg/k8s/apis/isovalent.com](../pkg/k8s/apis/isovalent.com).
Run:

    make generate

from the top-level directory to regenerated these files.

See [examples](examples) directory for example custom resources. These
examples are written manually. Add more examples if you feel like it.

# To Deploy sample write.yaml

$ kubectl apply -f ./isovalent.com_tracingpolicies.yaml
$ kubectl apply -f ./examples/write.yam
