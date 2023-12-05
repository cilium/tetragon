{{- define "container.tetragon-oci-hook-setup" -}}
- name: oci-hook-setup
  securityContext:
    {{- toYaml .Values.tetragon.ociHookSetup.securityContext | nindent 4 }}
  image: "{{ if .Values.tetragon.image.override }}{{ .Values.tetragon.image.override }}{{ else }}{{ .Values.tetragon.image.repository }}:{{ .Values.tetragon.image.tag | default .Chart.AppVersion }}{{ end }}"
  terminationMessagePolicy: FallbackToLogsOnError
  command: 
    - tetragon-oci-hook-setup
    - install
    - --interface={{ .Values.tetragon.ociHookSetup.interface }}
    - --local-install-dir={{  include "container.tetragonOCIHookSetup.installPath" . }}
    - --host-install-dir={{ .Values.tetragon.ociHookSetup.installDir }}
    - --oci-hooks.local-dir={{ include "container.tetragonOCIHookSetup.hooksPath" . }}
  volumeMounts:
    {{- with .Values.tetragon.ociHookSetup.extraVolumeMounts }}
      {{- toYaml . | nindent 4 }}
    {{- end }}
    - name: oci-hooks-path
      mountPath: {{  include "container.tetragonOCIHookSetup.hooksPath" . }}
    - name: oci-hooks-install-path
      mountPath: {{  include "container.tetragonOCIHookSetup.installPath" . }}
{{- with .Values.tetragon.ociHookSetup.resources }}
  resources: {}
    {{- toYaml . | nindent 4 }}
{{- end }}
{{- end -}}
