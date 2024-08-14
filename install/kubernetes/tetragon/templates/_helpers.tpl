{{/*
Common labels
*/}}
{{- define "commonLabels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "tetragon.labels" -}}
{{ include "tetragon.selectorLabels" . }}
{{ include "commonLabels" . }}
{{- end }}
{{- define "tetragon-operator.labels" -}}
{{ include "tetragon-operator.selectorLabels" . }}
{{ include "commonLabels" . }}
{{- end }}
{{- define "tetragon-rthooks.labels" -}}
{{ include "tetragon-rthooks.selectorLabels" . }}
{{ include "commonLabels" . }}
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
