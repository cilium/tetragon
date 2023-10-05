{{- define "container.tetragon" -}}
- name: {{ include "container.tetragon.name" . }}
  securityContext:
    {{- toYaml .Values.tetragon.securityContext | nindent 4 }}
  image: "{{ if .Values.tetragon.image.override }}{{ .Values.tetragon.image.override }}{{ else }}{{ .Values.tetragon.image.repository }}:{{ .Values.tetragon.image.tag | default .Chart.AppVersion }}{{ end }}"
  imagePullPolicy: {{ .Values.imagePullPolicy }}
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
    {{- if not .Values.tetragon.btf }}
    - mountPath: /var/lib/tetragon/metadata
      name: metadata-files
    {{- end }}
    - mountPath: /etc/tetragon/tetragon.conf.d/
      name: tetragon-config
      readOnly: true
    - mountPath: /sys/fs/bpf
      mountPropagation: Bidirectional
      name: bpf-maps
    - mountPath: "/var/run/cilium"
      name: cilium-run
    - mountPath: {{ .Values.exportDirectory }}
      name: export-logs
    - mountPath: "/procRoot"
      name: host-proc
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
{{- if .Values.tetragon.grpc.enabled }}
  livenessProbe:
     timeoutSeconds: 60
     exec:
       command:
       - tetra
       - status
       - --server-address
       - {{ .Values.tetragon.grpc.address }}
       - --retries
       - "5"
{{- end -}}
{{- end -}}

