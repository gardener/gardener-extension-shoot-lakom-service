// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package imagevector_test

import (
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/imagevector"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("imagevector", func() {
	It("Should successfully initialize image vector", func() {
		iv := imagevector.ImageVector()
		Expect(iv).To(Not(BeEmpty()))
	})

	It("Should successfully find lakom image", func() {
		iv := imagevector.ImageVector()
		image, err := iv.FindImage("lakom")
		Expect(err).To(Not(HaveOccurred()))
		Expect(image.Name).To(Equal("lakom"))
	})

	It("Should fail to find non-existing image", func() {
		iv := imagevector.ImageVector()
		_, err := iv.FindImage("foo-bar")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(`could not find image "foo-bar"`))
	})
})
