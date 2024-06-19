IMAGE_REPO=$(echo $SKAFFOLD_IMAGE | cut -d':' -f1,2)
IMAGE_TAG=$(echo $SKAFFOLD_IMAGE | cut -d':' -f3)

cat <<EOF > example/lakom/skaffold/patch-imagevector-overwrite.yaml
apiVersion: core.gardener.cloud/v1beta1
kind: ControllerDeployment
metadata:
  name: shoot-lakom-service
providerConfig:
  values:
    imageVectorOverwrite:
      images:
      - name: lakom
        repository: ${IMAGE_REPO}
        tag: ${IMAGE_TAG}
EOF
