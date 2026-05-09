{{- define "container.tetragon-rthooks" -}}
- name: tetragon-rthooks
  image: {{ include "rthooks.image" . }}
  terminationMessagePolicy: FallbackToLogsOnError
  imagePullPolicy: {{ .Values.imagePullPolicy }}
  command:
    - tetragon-oci-hook-setup
    - install
    - --interface={{ include "rthooksInterface" .  | required "rtooks.interface needs to be correctly defined" }}
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
    - --{{ $key }}
   {{- else }}
    - --{{ $key }}={{ $value }}
  {{- end }}
  {{- end }}
  volumeMounts:
    {{- with .Values.rthooks.extraVolumeMounts }}
      {{- toYaml . | nindent 4 }}
    {{- end }}
    - name: oci-hook-install-path
      mountPath: {{  include "container.tetragonOCIHookSetup.installPath" . }}
{{- if (eq .Values.rthooks.interface "oci-hooks") }}
    - name: oci-hooks-path
      mountPath: {{  include "container.tetragonOCIHookSetup.hooksPath" . }}
{{- end }}
{{- if (eq .Values.rthooks.interface "nri-hook") }}
    - name: nri-socket-path
      mountPath: {{ .Values.rthooks.nriHook.nriSocket }}
{{- end }}
{{- with .Values.rthooks.resources }}
  resources:
    {{- toYaml . | nindent 4 }}
{{- end }}
{{- end -}}

{{- define "container.tetragon-rthooks-export-logs" -}}
- name: export-logs
  image: {{ include "rthooks.image" . }}
  imagePullPolicy: {{ .Values.imagePullPolicy }}
  command:
    - tail
    - -F
    - {{ printf "%s/%s" .Values.rthooks.installDir "tetragon-oci-hook.log" | quote }}
  volumeMounts:
    - name: oci-hook-install-path
      mountPath: {{ .Values.rthooks.installDir | quote }}
      readOnly: true
{{- with .Values.rthooks.exportLogs.resources }}
  resources:
    {{- toYaml . | nindent 4 }}
{{- end }}
{{- end -}}
