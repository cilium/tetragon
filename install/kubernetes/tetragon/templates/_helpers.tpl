{{/*
Common labels
*/}}
{{- define "commonLabels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: {{ .Chart.Name }}
{{- end }}

{{/*
Fullname
*/}}
{{- define "tetragon.fullname" -}}
{{- if .Values.nameOverride -}}
{{- printf "%s" .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
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
app.kubernetes.io/instance: {{ include "tetragon.fullname" . }}
{{- end }}

{{- define "tetragon-operator.selectorLabels" -}}
app.kubernetes.io/name: "tetragon-operator"
app.kubernetes.io/instance: {{ include "tetragon.fullname" . }}
{{- end }}

{{- define "tetragon-rthooks.selectorLabels" -}}
app.kubernetes.io/name: "tetragon-rthooks"
app.kubernetes.io/instance: {{ include "tetragon.fullname" . }}
{{- end }}

{{/*
ServiceAccount names
*/}}
{{- define "tetragon.serviceAccount" -}}
{{- if .Values.serviceAccount.name -}}
{{- printf "%s" .Values.serviceAccount.name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s" (include "tetragon.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "tetragon-operator.serviceAccount" -}}
{{- if .Values.tetragonOperator.serviceAccount.name -}}
{{- printf "%s" .Values.tetragonOperator.serviceAccount.name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-operator-service-account" (include "tetragon.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "container.export.stdout.name" -}}
{{- print "export-stdout" -}}
{{- end }}

{{- define "container.tetragon.name" -}}
{{- print "tetragon" -}}
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
