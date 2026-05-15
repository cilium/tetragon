{{/*
Reusable PodSpec / JobSpec body for the certgen Job and CronJob. Renders the
cilium-certgen invocation that (re)creates the server + CA Secrets for the
tetragon gRPC TLS listener.
*/}}
{{- define "tetragon.certgen.jobSpec" -}}
{{- $validityHours := mul .Values.tetragon.grpc.tls.auto.certValidityDuration 24 -}}
{{- $validityStr := printf "%dh" $validityHours -}}
{{- $caValidityHours := mul .Values.tetragon.grpc.tls.ca.certValidityDuration 24 -}}
{{- $caValidityStr := printf "%dh" $caValidityHours -}}
spec:
  template:
    metadata:
      labels:
        {{- include "tetragon.labels" . | nindent 8 }}
        app.kubernetes.io/component: certgen
        {{- with .Values.certgen.podLabels }}
        {{- toYaml . | nindent 8 }}
        {{- end }}
    spec:
      restartPolicy: OnFailure
      serviceAccountName: {{ include "tetragon.name" . }}-certgen
      securityContext:
        runAsNonRoot: true
        runAsUser: 65534
        runAsGroup: 65534
        seccompProfile:
          type: RuntimeDefault
      {{- with .Values.certgen.nodeSelector }}
      nodeSelector:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- with .Values.certgen.tolerations }}
      tolerations:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- with .Values.certgen.affinity }}
      affinity:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- with .Values.imagePullSecrets }}
      imagePullSecrets:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      containers:
        - name: certgen
          image: "{{ if .Values.certgen.image.override }}{{ .Values.certgen.image.override }}{{ else }}{{ .Values.certgen.image.repository }}:{{ .Values.certgen.image.tag }}{{ end }}"
          imagePullPolicy: {{ .Values.certgen.image.pullPolicy }}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
          command:
            - "/usr/bin/cilium-certgen"
          args:
            - "--ca-generate={{ .Values.certgen.generateCA }}"
            - "--ca-reuse-secret"
            - "--ca-secret-namespace={{ .Release.Namespace }}"
            - "--ca-secret-name={{ include "tetragon.caSecretName" . }}"
            - "--ca-common-name=Tetragon CA"
            - "--ca-validity-duration={{ $caValidityStr }}"
          env:
            - name: CILIUM_CERTGEN_CONFIG
              value: |
                certs:
                  - name: {{ include "tetragon.grpcTlsSecretName" . }}
                    namespace: {{ .Release.Namespace }}
                    commonName: {{ include "tetragon.grpcTls.commonName" . | quote }}
                    hosts:
                      - {{ include "tetragon.grpcTls.commonName" . | quote }}
                      {{- range .Values.tetragon.grpc.tls.server.extraDnsNames }}
                      - {{ . | quote }}
                      {{- end }}
                      {{- range .Values.tetragon.grpc.tls.server.extraIpAddresses }}
                      - {{ . | quote }}
                      {{- end }}
                    usage:
                      - signing
                      - key encipherment
                      - server auth
                      - client auth
                    validity: {{ $validityStr }}
          {{- with .Values.certgen.resources }}
          resources:
            {{- toYaml . | nindent 12 }}
          {{- end }}
{{- end -}}
