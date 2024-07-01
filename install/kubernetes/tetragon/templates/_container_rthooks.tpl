{{- define "container.tetragon-rthooks" -}}
- name: tetragon-rthooks
  securityContext:
    {{- toYaml .Values.rthooks.securityContext | nindent 4 }}
  image: "{{ if .Values.rthooks.image.override }}{{ .Values.rthooks.image.override }}{{ else }}{{ .Values.rthooks.image.repository }}:{{ .Values.rthooks.image.tag }}{{ end }}"
  terminationMessagePolicy: FallbackToLogsOnError
  imagePullPolicy: {{ .Values.imagePullPolicy }}
  command: 
    - tetragon-oci-hook-setup
    - install
    - --interface={{ .Values.rthooks.interface }}
    - --local-install-dir={{  include "container.tetragonOCIHookSetup.installPath" . }}
    - --host-install-dir={{ .Values.rthooks.installDir }}
    - --oci-hooks.local-dir={{ include "container.tetragonOCIHookSetup.hooksPath" . }}
    - --daemonize
    - hook-args
    - --grpc-address={{ .Values.tetragon.grpc.address }}
    - --fail-allow-namespaces
    - {{ if .Values.rthooks.failAllowNamespaces }}{{ printf "%s,%s" .Release.Namespace .Values.rthooks.failAllowNamespaces }}{{ else }}{{ .Release.Namespace }}{{ end }}
   {{- range $key, $value := .Values.rthooks.extraHookArgs }}
   {{- if eq nil $value }}
    - {{ $key }}
    - {{ $value }}
   {{- else }}
    - {{ $key }}
  {{- end }}
  {{- end }}
  volumeMounts:
    {{- with .Values.rthooks.extraVolumeMounts }}
      {{- toYaml . | nindent 4 }}
    {{- end }}
    - name: oci-hooks-path
      mountPath: {{  include "container.tetragonOCIHookSetup.hooksPath" . }}
    - name: oci-hook-install-path
      mountPath: {{  include "container.tetragonOCIHookSetup.installPath" . }}
{{- with .Values.rthooks.resources }}
  resources: {}
    {{- toYaml . | nindent 4 }}
{{- end }}
{{- end -}}
