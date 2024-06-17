cat <<EOF > local-setup/patch-imagevector-overwrite.yaml
apiVersion: core.gardener.cloud/v1beta1
kind: ControllerDeployment
metadata:
  name: shoot-lakom-service
providerConfig:
  values:
    imageVectorOverwrite:
      images:
      - name: lakom
        repository: ${SKAFFOLD_IMAGE_REPO}
        tag: ${SKAFFOLD_IMAGE_TAG}
EOF
