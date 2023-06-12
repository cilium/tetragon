{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "tetragon.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- define "tetragon-operator.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- define "tetragonPod-controller.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "tetragon.labels" -}}
helm.sh/chart: {{ include "tetragon.chart" . }}
{{ include "tetragon.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}
{{- define "tetragon-operator.labels" -}}
helm.sh/chart: {{ include "tetragon-operator.chart" . }}
{{ include "tetragon-operator.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}
{{- define "tetragonPod-controller.labels" -}}
helm.sh/chart: {{ include "tetragonPod-controller.chart" . }}
{{ include "tetragonPod-controller.selectorLabels" . }}
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
{{- define "tetragonPod-controller.selectorLabels" -}}
app.kubernetes.io/name: "tetragonPod-controller"
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "container.export.stdout.name" -}}
{{- print "export-stdout" -}}
{{- end }}

{{- define "container.tetragon.name" -}}
{{- print "tetragon" -}}
{{- end }}
