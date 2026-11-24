// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package imagevector

import (
	"github.com/gardener/gardener-extension-shoot-lakom-service/charts"

	"github.com/gardener/gardener/pkg/utils/imagevector"
	"k8s.io/apimachinery/pkg/util/runtime"
)

var (
	imageVector imagevector.ImageVector
	caBundle    *imagevector.CABundle
)

func init() {
	var err error

	imageVector, caBundle, err = imagevector.Read([]byte(charts.ImagesYAML))
	runtime.Must(err)

	imageVector, caBundle, err = imagevector.WithEnvOverride(imageVector, caBundle, imagevector.OverrideEnv)
	runtime.Must(err)
}

// ImageVector is the image vector that contains all the needed images.
func ImageVector() imagevector.ImageVector {
	return imageVector
}

// CABundle returns the CA bundle defined in the container image vector.
func CABundle() *imagevector.CABundle {
	return caBundle
}
