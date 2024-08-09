#!/bin/bash
# vim:set noet ci pi ts=4 sw=4

set -o pipefail
set -e

# This tests that the values we extract from container annotations match whatever ends up
# in the pod
#
# Example:
#   minikube start --driver=docker --container-runtime=cri-o
#   ./scripts/minikube-install-hook.sh -l
#   ./scripts/minikube-test-hook.sh

SCRIPTPATH=$(dirname "$0")

source ${SCRIPTPATH}/helpers
runtime=$(detect_runtime)
echo "Runtime: $runtime"

ns="pizza"
pod_name="pod-pizza"

kubectl create namespace $ns || true
kubectl apply -n $ns -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${pod_name}
spec:
  containers:
  - name: container-pizza
    image: alpine
    command: ["/bin/sleep","1d"]
EOF

declare -A podJqExpr=(
	# NB: sub removes <cri>:// prefix
	[containerID]=".status.containerStatuses[0].containerID | sub(\"^.+://\"; \"\")"
	[containerName]=".status.containerStatuses[0].name"
	[podID]=".metadata.uid"
	[podName]=".metadata.name"
	[podNamespace]=".metadata.namespace"
)

declare -A logJqExpr=(
	[containerID]='.["req-containerID"]'
	[containerName]='.["req-containerName"]'
	[podID]='.["req-podUID"]'
	[podName]='.["req-podName"]'
	[podNamespace]='.["req-podNamespace"]'
)

kubectl wait -n $ns --for=condition=ready pod $pod_name || (kubectl describe pod/$pod_name && false)

pod=$(mktemp --tmpdir pod-XXXX)
kubectl -n $ns get pods/$pod_name -o json > $pod
log=$(mktemp --tmpdir log-XXXX)
minikube ssh 'cat /opt/tetragon/tetragon-oci-hook.log' > $log

podID=$(jq --raw-output "${podJqExpr[podID]}" < $pod)
line=$(jq -c --arg podID $podID ". | select(${logJqExpr[podID]} == \$podID)" < $log)
if [ -z "$line" ]; then
	echo "Failed to find log line for pod id '$podID'"
	exit 1
fi

echo "Found line matches podname ($pod_name):"
echo $line | jq .


error=0
for field in "${!podJqExpr[@]}"; do
	podval=$(jq --raw-output "${podJqExpr[$field]}" < $pod)
	logval=$(echo $line | jq --raw-output "${logJqExpr[$field]}")
	if [ "$logval" = "$podval" ]; then
		continue
	fi

	# NB: containerd does not support containerID annotation
	if [ $runtime = "containerd" ] && [ $field = "containerID" ] && [ "$logval" = "" ]; then
		continue
	fi

	echo "Mismatch:$field log:$logval vs podval:$podval"
	error=1
done

if [ $error -eq 0 ]; then
	echo "Test successful"
fi

exit $error
