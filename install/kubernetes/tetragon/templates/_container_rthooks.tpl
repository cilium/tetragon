{{- define "container.tetragon-rthooks" -}}
- name: tetragon-rthooks
  image: {{ include "rthooks.image" . }}
  terminationMessagePolicy: FallbackToLogsOnError
  imagePullPolicy: {{ .Values.imagePullPolicy | quote }}
  command:
    - tetragon-oci-hook-setup
    - install
    - {{ printf "--interface=%v" (include "rthooksInterface" . | required "rtooks.interface needs to be correctly defined") | quote }}
    - --local-install-dir={{  include "container.tetragonOCIHookSetup.installPath" . }}
    - {{ printf "--host-install-dir=%v" .Values.rthooks.installDir | quote }}
    - --oci-hooks.local-dir={{ include "container.tetragonOCIHookSetup.hooksPath" . }}
    - --daemonize
    - hook-args
    - {{ printf "--grpc-address=%v" .Values.tetragon.grpc.address | quote }}
    - --fail-allow-namespaces
    - {{ if .Values.rthooks.failAllowNamespaces }}{{ printf "%v,%v" .Release.Namespace .Values.rthooks.failAllowNamespaces | quote }}{{ else }}{{ .Release.Namespace | quote }}{{ end }}
   {{- range .Values.rthooks.failAllowNamespacesRegex }}
    - {{ printf "--fail-allow-namespaces-regex=%v" . | quote }}
   {{- end }}
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
      mountPath: {{ .Values.rthooks.nriHook.nriSocket | quote }}
{{- end }}
{{- with .Values.rthooks.resources }}
  resources:
    {{- toYaml . | nindent 4 }}
{{- end }}
{{- end -}}

{{- define "container.tetragon-rthooks-export-logs" -}}
- name: export-logs
  image: {{ include "rthooks.image" . }}
  imagePullPolicy: {{ .Values.imagePullPolicy | quote }}
  command:
    - tail
    - -F
    - {{ printf "%v/%v" .Values.rthooks.installDir "tetragon-oci-hook.log" | quote }}
  volumeMounts:
    - name: oci-hook-install-path
      mountPath: {{ .Values.rthooks.installDir | quote }}
      readOnly: true
{{- with .Values.rthooks.exportLogs.resources }}
  resources:
    {{- toYaml . | nindent 4 }}
{{- end }}
{{- end -}}
