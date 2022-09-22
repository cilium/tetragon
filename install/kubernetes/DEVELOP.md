# Using the Latest Unreleased Chart

The latest `tetragon` Helm chart from the main branch is published as version `9999.9999.9999-dev`.
You can use the latest chart as a "standalone" chart for testing. For example, to install the latest Tetragon
with the latest `tetragon` Helm chart on minikube:

0. Start minikube. Something like this:

       minikube start --network-plugin=cni --memory=4096 --driver=virtualbox \
         --iso-url=https://github.com/kubernetes/minikube/releases/download/v1.15.0/minikube-v1.15.0.iso
       minikube ssh -- sudo mount bpffs -t bpf /sys/fs/bpf

   Check https://docs.cilium.io/quick-start/connectivity_visibility.html#start-minikube for the up-to-date
   instructions on how to start minikube.

1. Install `tetragon`, specifying the image tag you are using:

       helm install -n kube-system tetragon install/kubernetes \
         --set tetragon.image.tag=latest --set imagePullPolicy=Always

   Alternatively, if you want to use the local chart to test your change, run:

       helm install -n kube-system tetragon . \
         --set tetragonOperator.image.tag=latest --set imagePullPolicy=Always
