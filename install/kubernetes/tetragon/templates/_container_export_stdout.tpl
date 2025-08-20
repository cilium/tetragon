{{- define "container.export.stdout" -}}
- name: {{include "container.export.stdout.name" .}}
  image: "{{ if .Values.export.stdout.image.override }}{{ .Values.export.stdout.image.override }}{{ else }}{{ .Values.export.stdout.image.repository }}:{{ .Values.export.stdout.image.tag }}{{ end }}"
  imagePullPolicy: {{ .Values.imagePullPolicy }}
  terminationMessagePolicy: FallbackToLogsOnError
  {{- with .Values.export.stdout.extraEnv }}
  env:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- $envFrom := list }}
  {{- with .Values.export.stdout.extraEnvFrom }}
    {{- $envFrom = concat $envFrom . }}
  {{- end }}
  {{- range $item := .Values.export.stdout.envFromSecrets }}
    {{- if kindIs "map" $item }}
      {{- $sr := dict "name" ($item.name | default "") }}
      {{- if hasKey $item "optional" }}
        {{- $_ := set $sr "optional" $item.optional }}
      {{- end }}
      {{- $envFrom = append $envFrom (dict "secretRef" $sr) }}
    {{- else }}
      {{- $envFrom = append $envFrom (dict "secretRef" (dict "name" $item)) }}
    {{- end }}
  {{- end }}
  {{- if gt (len $envFrom) 0 }}
  envFrom:
    {{- toYaml $envFrom | nindent 4 }}
  {{- end }}
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
