{{- /*
Mounts bpffs on the host when the agent is not privileged, so that pinned
programs and maps outlive the agent container. The agent container can only
use HostToContainer propagation in that case, which can't push a mount back to
the host.
*/}}
{{- define "container.mount-bpf-fs" -}}
- name: mount-bpf-fs
  image: {{ include "tetragon.image" . }}
  imagePullPolicy: {{ .Values.imagePullPolicy }}
  terminationMessagePolicy: FallbackToLogsOnError
  command:
    - /bin/sh
    - -c
  {{- /* Busybox mount lists nothing without arguments, read /proc/mounts instead. */}}
  args:
    - 'grep -q " /sys/fs/bpf bpf " /proc/mounts || mount -t bpf bpf /sys/fs/bpf'
  securityContext:
    privileged: true
  volumeMounts:
    - mountPath: /sys/fs/bpf
      {{- /* Required to propagate the mount to the host. */}}
      mountPropagation: Bidirectional
      name: bpf-maps
{{- end }}
