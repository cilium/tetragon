{{- define "container.export.stdout" -}}
- name: {{include "container.export.stdout.name" .}}
  image: "{{ if .Values.export.stdout.image.override }}{{ .Values.export.stdout.image.override }}{{ else }}{{ .Values.export.stdout.image.repository }}:{{ .Values.export.stdout.image.tag }}{{ end }}"
  imagePullPolicy: {{ .Values.imagePullPolicy }}
  env: {{- toYaml .Values.export.extraEnv | nindent 4 }}
  securityContext:
    {{- toYaml .Values.export.securityContext | nindent 4 }}
  resources:
    {{- toYaml .Values.export.resources | nindent 4 }}
  command:
    - hubble-export-stdout
  args:
{{- range .Values.export.filenames }}
    - {{ $.Values.exportDirectory }}/{{ . }}
{{- end }}
  volumeMounts:
    - name: export-logs
      mountPath: {{ .Values.exportDirectory }}
{{- end }}
