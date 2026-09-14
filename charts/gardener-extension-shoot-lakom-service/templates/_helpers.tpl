{{-  define "image" -}}
  {{- if hasPrefix "sha256:" .Values.image.tag }}
  {{- printf "%s@%s" .Values.image.repository .Values.image.tag }}
  {{- else }}
  {{- printf "%s:%s" .Values.image.repository .Values.image.tag }}
  {{- end }}
{{- end }}

{{- define "leaderelectionid" -}}
extension-shoot-lakom-service-leader-election
{{- end -}}

{{- define "name" -}}
{{- /* TODO(vpnachev): Remove gardener.runtimeCluster.enabled, replaced by gardener.clusterTypes.gardenRuntimeCluster, it will be no longer supported by Gardener after v1.159.0 is released. */}}
{{- if (or .Values.gardener.clusterTypes.gardenRuntimeCluster .Values.gardener.runtimeCluster.enabled) -}}
shoot-lakom-service-runtime
{{- else -}}
shoot-lakom-service
{{- end -}}
{{- end -}}
