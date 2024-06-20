This is a dev demo of how to install the teragon OCI hook on a CRI-O runtime.

Note: we should move this to the documentation once the PR is merged and `tetragon-oci-hook` and
`tetragon-oci-hook-setup` are part of the tetragon development image.


Start minikube:

```shell-session
minikube start --driver=kvm2 --container-runtime=cri-o
```

Build images and load them to minikube:

```shell-session
make image image-operator
minikube image load cilium/tetragon:latest
minikube image load cilium/tetragon-operator:latest
minikube image list | grep tetragon
localhost/cilium/tetragon:latest
localhost/cilium/tetragon-operator:latest
```

Install the image enabling the init container:

```
helm install --namespace kube-system \
        --set tetragonOperator.image.override=localhost/cilium/tetragon-operator:latest \
        --set tetragon.image.override=localhost/cilium/tetragon:latest  \
        --set tetragon.grpc.address="unix:///var/run/cilium/tetragon/tetragon.sock" \
        --set tetragon.ociHookSetup.enabled=true \
        tetragon ./install/kubernetes/tetragon
...
kubectl logs -n kube-system tetragon-289tf  -c oci-hook-setup
time="2023-12-05T09:28:50Z" level=info msg="written binary" hook-dst-path=/hostInstall/tetragon-oci-hook
time="2023-12-05T09:28:50Z" level=info msg="written conf" conf-dst-path=/hostHooks/tetragon-oci-hook.json
```

Check the hook looks:
```
minikube ssh -- tail -f /opt/tetragon/tetragon-oci-hook.log 
...
time="2023-12-05T09:31:08Z" level=info msg="hook request to agent succeeded" hook=create-container ...
```

You can now uninstall tetragon:
```
helm uninstall -n kube-system tetragon
```

In many situations, you would want the hook to keep running even if tetragon is
not. Doing so, will allow you to configure a class of pods that can only run if tetragon is availble.


To uninstall the hook, you can install the following daemonset:
```
kubectl -n  kube-system  apply -f contrib/rthooks/tetragon-oci-hook/k8s/ds-uninstall.yaml
kubectl -n kube-system logs tetragon-oci-hook-uninstall-8t4bl -c setup
time="2023-12-05T09:37:37Z" level=info msg="conf removed" conf-dst-path=/hostHooks/tetragon-oci-hook.json error="<nil>"
time="2023-12-05T09:37:37Z" level=info msg="binary removed" bin-dst-path=/hostInstall/tetragon-oci-hook error="<nil>"
```

(NB: above is not ideal, we should find a better way to do this)
