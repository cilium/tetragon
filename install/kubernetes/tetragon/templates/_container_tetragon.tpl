{{- define "container.tetragon" -}}
- name: {{ include "container.tetragon.name" . }}
  securityContext:
    {{- toYaml .Values.tetragon.securityContext | nindent 4 }}
  image: {{ include "tetragon.image" . }}
  imagePullPolicy: {{ .Values.imagePullPolicy }}
  terminationMessagePolicy: FallbackToLogsOnError
{{- with .Values.tetragon.commandOverride }}
  command:
  {{- toYaml . | nindent 2 }}
{{- end }}
  args:
    - --config-dir=/etc/tetragon/tetragon.conf.d/
{{- with .Values.tetragon.argsOverride }}
  {{- toYaml . | nindent 2 }}
{{- else }}
{{- range $key, $value := .Values.tetragon.extraArgs }}
{{- if $value }}
    - --{{ $key }}={{ $value }}
{{- else }}
    - --{{ $key }}
{{- end }}
{{- end }}
{{- end }}
  volumeMounts:
    {{- with .Values.tetragon.extraVolumeMounts }}
      {{- toYaml . | nindent 4 }}
    {{- end }}
    - mountPath: /etc/tetragon/tetragon.conf.d/
      name: tetragon-config
      readOnly: true
    - mountPath: /sys/fs/bpf
      {{- /* Bidirectional propagation is only allowed for privileged containers,
      otherwise the mount-bpf-fs init container mounts bpffs on the host. */}}
      {{- if .Values.tetragon.securityContext.privileged }}
      mountPropagation: Bidirectional
      {{- else }}
      mountPropagation: HostToContainer
      {{- end }}
      name: bpf-maps
    - mountPath: "/var/run/cilium"
      name: cilium-run
    - mountPath: "/var/run/tetragon"
      name: tetragon-run
    - mountPath: {{ .Values.exportDirectory }}
      name: export-logs
    - mountPath: "/procRoot"
      name: host-proc
{{- if and (.Values.tetragon.cri.enabled) (.Values.tetragon.cri.socketHostPath) }}
    - mountPath: {{ dir .Values.tetragon.cri.socketHostPath | quote }}
      name: cri-socket
{{- end }}
{{- if and .Values.tetragon.grpc.enabled .Values.tetragon.grpc.tls.enabled }}
    - mountPath: /var/lib/tetragon/tls
      name: tetragon-grpc-tls
      readOnly: true
{{- end }}
{{- range .Values.extraHostPathMounts }}
    - name: {{ .name }}
      mountPath: {{ .mountPath }}
      readOnly: {{ .readOnly }}
{{- if .mountPropagation }}
      mountPropagation: {{ .mountPropagation }}
{{- end }}
{{- end }}
{{- range .Values.extraConfigmapMounts }}
    - name: {{ .name }}
      mountPath: {{ .mountPath }}
      readOnly: {{ .readOnly }}
{{- end }}
    {{- include "tetragon.volumemounts.extra" . | nindent 4 }}
  env:
    - name: NODE_NAME
      valueFrom:
        fieldRef:
            fieldPath: spec.nodeName
{{- if .Values.tetragon.extraEnv }}
  {{- toYaml .Values.tetragon.extraEnv | nindent 4 }}
{{- end }}
{{- with .Values.tetragon.resources }}
  resources:
    {{- toYaml . | nindent 4 }}
{{- end }}
{{- if .Values.tetragon.livenessProbe }}
  livenessProbe:
  {{- toYaml .Values.tetragon.livenessProbe | nindent 4 }}
{{- else if .Values.tetragon.healthGrpc.enabled }}
  livenessProbe:
     timeoutSeconds: 60
     grpc:
      port: {{ .Values.tetragon.healthGrpc.port }}
      service: "liveness"
{{- end -}}
{{- if .Values.tetragon.startupProbe }}
  startupProbe:
  {{- toYaml .Values.tetragon.startupProbe | nindent 4 }}
{{- else if .Values.tetragon.healthGrpc.enabled }}
  startupProbe:
     timeoutSeconds: 60
     grpc:
      port: {{ .Values.tetragon.healthGrpc.port }}
      service: "startup"
{{- end -}}
{{- end -}}

