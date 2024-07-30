# SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0


# Ideally we'd use $SKAFFOLD_IMAGE_REPO & $SKAFFOLD_IMAGE_TAG instead of
# extracting these values from $SKAFFOLD_IMAGE, but for some reason,
# the value for $SKAFFOLD_IMAGE_REPO is everything before the '/' symbol, instead
# of everything before the last ':' symbol (where the image tag should start)
# e.g. For SKAFFOLD_IMAGE=localhost:5001/lakom:tag
# SKAFFOLD_IMAGE_REPO=localhost:5001 (instead of localhost:5001/lakom)
# SKAFFOLD_IMAGE_TAG=tag
#
# This might need to be brought up as an issue on skaffold's side. For anyone
# interested, the logic for the parsing of the image name in the skaffold project 
# is contained in https://github.com/GoogleContainerTools/skaffold/blob/main/pkg/skaffold/docker/reference.go

set -o pipefail
set -o errexit

image_repo=$(echo $SKAFFOLD_IMAGE | cut -d':' -f1,2)
image_tag=$(echo $SKAFFOLD_IMAGE | cut -d':' -f3)

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
        repository: ${image_repo}
        tag: ${image_tag}
EOF
