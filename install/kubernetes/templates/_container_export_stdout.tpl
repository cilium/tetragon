{{- define "container.export.stdout" -}}
- name: {{include "container.export.stdout.name" .}}
  image: "{{ if .Values.export.stdout.image.override }}{{ .Values.export.stdout.image.override }}{{ else }}{{ .Values.export.stdout.image.repository }}:{{ .Values.export.stdout.image.tag }}{{ end }}"
  imagePullPolicy: {{ .Values.imagePullPolicy }}
  env: {{- toYaml .Values.export.extraEnv | nindent 4 }}
  securityContext:
    {{- toYaml .Values.export.securityContext | nindent 4 }}
  resources:
    {{- toYaml .Values.export.resources | nindent 4 }}
{{- if .Values.export.stdout.enabledCommand }}  
  command:
  {{- with .Values.export.stdout.commandOverride }}
  {{- toYaml . | nindent 3 }}
  {{- else }}
    - hubble-export-stdout
  {{- end }}
{{- end}}
{{- if .Values.export.stdout.enabledArgs }}  
  args:
  {{- with .Values.export.stdout.argsOverride }}
  {{- toYaml . | nindent 3 }}
  {{- else }}
  {{- range .Values.export.filenames }}
    - {{ $.Values.exportDirectory }}/{{ . }}
  {{- end }}
  {{- end }}
{{- end }}
  volumeMounts:
    - name: export-logs
      mountPath: {{ .Values.exportDirectory }}
      {{- with .Values.export.stdout.extraVolumeMounts }}
        {{- toYaml . | nindent 4 }}
      {{- end }}      
{{- end }}
