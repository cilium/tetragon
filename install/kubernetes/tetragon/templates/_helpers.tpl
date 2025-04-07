{{/*
Common labels
*/}}
{{- define "commonLabels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: {{ .Chart.Name }}
{{- end }}

{{- define "tetragon.labels" -}}
{{ include "tetragon.selectorLabels" . }}
{{ include "commonLabels" . }}
app.kubernetes.io/component: agent
{{- end }}
{{- define "tetragon-operator.labels" -}}
{{ include "tetragon-operator.selectorLabels" . }}
{{ include "commonLabels" . }}
app.kubernetes.io/component: operator
{{- end }}
{{- define "tetragon-rthooks.labels" -}}
{{ include "tetragon-rthooks.selectorLabels" . }}
{{ include "commonLabels" . }}
app.kubernetes.io/component: rthooks
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
{{- define "tetragon-rthooks.selectorLabels" -}}
app.kubernetes.io/name: "tetragon-rthooks"
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

{{/*
Runtime-hooks
*/}}

{{- define "rthooksInterface" -}}
{{ $iface := .Values.rthooks.interface }}
{{- if (eq $iface "oci-hooks") -}}
	oci-hooks
{{- else if (eq $iface "nri-hook") -}}
	nri-hook
{{- else -}}
{{- end -}}
{{- end }}


{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
*/}}
{{- define "tetragon.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
