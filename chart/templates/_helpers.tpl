{{/*
Expand the name of the chart.
*/}}
{{- define "pint.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.  If the release name already contains
the chart name, use the release name alone to avoid repetition (e.g. "pint-pint").
*/}}
{{- define "pint.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "pint.serviceAccountName" -}}
{{- default (include "pint.fullname" .) .Values.serviceAccount.name }}
{{- end }}

{{/*
Standard Helm labels / selector labels for the PINT pod.
*/}}
{{- define "pint.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "pint.selectorLabels" . }}
app.kubernetes.io/version: {{ default .Chart.AppVersion .Values.pint.image.tag | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "pint.selectorLabels" -}}
app.kubernetes.io/name: {{ include "pint.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Runtime-managed secret names.
These default to "<fullname>-<suffix>" so multiple releases in the same namespace
never collide. Each can be overridden via the corresponding values key.
*/}}
{{- define "pint.secretName.config" -}}
{{- .Values.secrets.config | default (printf "%s-config" (include "pint.fullname" .)) }}
{{- end }}

{{- define "pint.secretName.radSecCert" -}}
{{- .Values.secrets.radSecCert | default (printf "%s-radsec-server-certificates" (include "pint.fullname" .)) }}
{{- end }}

{{- define "pint.secretName.profileSigningCert" -}}
{{- .Values.secrets.profileSigningCert | default (printf "%s-profile-signing-cert" (include "pint.fullname" .)) }}
{{- end }}

{{- define "pint.secretName.scepRACert" -}}
{{- .Values.secrets.scepRACert | default (printf "%s-scep-ra-cert" (include "pint.fullname" .)) }}
{{- end }}

{{- define "pint.envSecret" -}}
{{- .Values.envSecret | default (include "pint.fullname" .) }}
{{- end }}

{{/*
FreeRADIUS labels / selector labels.
The selector string is also injected into PINT as PINT_FREERADIUS_POD_SELECTOR
so it always matches these labels exactly.
*/}}
{{- define "pint.freeradiusFullname" -}}
{{- printf "%s-freeradius" (include "pint.fullname" .) }}
{{- end }}

{{- define "pint.freeradiusLabels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "pint.freeradiusSelectorLabels" . }}
app.kubernetes.io/version: {{ default .Chart.AppVersion .Values.freeradius.image.tag | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "pint.freeradiusSelectorLabels" -}}
app.kubernetes.io/name: {{ include "pint.freeradiusFullname" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "pint.freeradiusPodSelector" -}}
app.kubernetes.io/name={{ include "pint.freeradiusFullname" . }},app.kubernetes.io/instance={{ .Release.Name }}
{{- end }}

{{/*
Container image references: tag falls back to Chart.appVersion.
*/}}
{{- define "pint.image" -}}
{{ .Values.pint.image.repository }}:{{ default .Chart.AppVersion .Values.pint.image.tag }}
{{- end }}

{{- define "pint.freeradiusImage" -}}
{{ .Values.freeradius.image.repository }}:{{ default .Chart.AppVersion .Values.freeradius.image.tag }}
{{- end }}
