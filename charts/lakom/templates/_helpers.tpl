{{-  define "image" -}}
  {{- if hasPrefix "sha256:" .Values.image.tag }}
  {{- printf "%s@%s" .Values.image.repository .Values.image.tag }}
  {{- else }}
  {{- printf "%s:%s" .Values.image.repository .Values.image.tag }}
  {{- end }}
{{- end }}

{{- define "lakom.cosignPublicKeys" -}}
{{- range .Values.cosign.publicKeys -}}
{{- printf "%s\n" . -}}
{{- end -}}
{{- end -}}