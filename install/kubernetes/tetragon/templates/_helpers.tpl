{{/*
Resources names
*/}}
{{- define "tetragon.name" -}}
{{- default .Release.Name .Values.tetragon.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "tetragon.configMapName" -}}
{{- printf "%s-config" (include "tetragon.name" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "tetragon.clusterRole" -}}
{{- include "tetragon.name" . }}
{{- end }}

{{- define "tetragon.role" -}}
{{- include "tetragon.name" . }}
{{- end }}

{{- define "tetragon-operator.name" -}}
{{- default (printf "%s-operator" .Release.Name) .Values.tetragonOperator.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "tetragon-operator.clusterRole" -}}
{{- include "tetragon-operator.name" . }}
{{- end }}

{{- define "tetragon-operator.roleBindingName" -}}
{{- printf "%s-rolebinding" (include "tetragon-operator.name" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "tetragon-operator.configMapName" -}}
{{- printf "%s-config" (include "tetragon-operator.name" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "tetragon-rthooks.name" -}}
{{- default (printf "%s-rthooks" .Release.Name) .Values.rthooks.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}


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
{{- include "tetragon.name" . -}}
{{- end -}}
{{- end }}

{{- define "tetragon-operator.serviceAccount" -}}
{{- if .Values.tetragonOperator.serviceAccount.name -}}
{{- printf  "%s" .Values.tetragonOperator.serviceAccount.name -}}
{{- else -}}
{{- printf  "%s-service-account" (include "tetragon-operator.name" .) -}}
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
