{{- define "strait.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "strait.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else if contains (include "strait.name" .) .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name (include "strait.name" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "strait.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{ include "strait.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "strait.selectorLabels" -}}
app.kubernetes.io/name: {{ include "strait.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "strait.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "strait.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/* Port number at the end of a "host:port" address. */}}
{{- define "strait.port" -}}
{{- regexFind "[0-9]+$" . | int }}
{{- end }}

{{/* Valid Kubernetes port name (lowercase, at most 15 characters) from a listener name. */}}
{{- define "strait.portName" -}}
{{- regexReplaceAll "[^a-z0-9-]" (lower .) "-" | trunc 15 | trimSuffix "-" }}
{{- end }}

{{/* Fails the render when a listener watches another namespace without clusterWide RBAC. */}}
{{- define "strait.checkNamespaces" -}}
{{- range .Values.config.listeners }}
{{- with .kubernetes }}
{{- if and .namespace (ne .namespace $.Release.Namespace) (not $.Values.rbac.clusterWide) }}
{{- fail (printf "listener watches namespace %q; set rbac.clusterWide=true to allow it" .namespace) }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}
