{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "tetragon.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- define "tetragon-operator.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "tetragon.labels" -}}
helm.sh/chart: {{ include "tetragon.chart" . }}
{{ include "tetragon.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}
{{- define "tetragon-operator.labels" -}}
helm.sh/chart: {{ include "tetragon-operator.chart" . }}
{{ include "tetragon-operator.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "tetragon.selectorLabels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
{{- define "tetragon-operator.selectorLabels" -}}
app.kubernetes.io/name: "tetragon-operator"
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "container.export.stdout.name" -}}
{{- print "export-stdout" -}}
{{- end }}

{{- define "container.tetragon.name" -}}
{{- print "tetragon" -}}
{{- end }}

{{/*
ServiceAccounts
*/}}
{{- define "tetragon.serviceAccount" -}}
{{- if .Values.serviceAccount.name -}}
{{- printf "%s" .Values.serviceAccount.name -}}
{{- else -}}
{{- printf "%s" .Release.Name -}}
{{- end -}}
{{- end }}

{{- define "tetragon-operator.serviceAccount" -}}
{{- if .Values.tetragonOperator.serviceAccount.name -}}
{{- printf  "%s" .Values.tetragonOperator.serviceAccount.name -}}
{{- else -}}
{{- printf  "%s-operator-service-account" .Release.Name -}}
{{- end -}}
{{- end }}

{{- define "container.tetragonOCIHookSetup.installPath" -}}
{{- print "/hostInstall" -}}
{{- end }}

{{- define "container.tetragonOCIHookSetup.hooksPath" -}}
{{- print "/hostHooks" -}}
{{- end }}
