// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package utils_test

import (
	"crypto/tls"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/lakom/utils"

	secretsutils "github.com/gardener/gardener/pkg/utils/secrets"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("RegistryTransport", func() {
	It("Should return no transport when no CA directory is configured", func() {
		transport, err := utils.RegistryTransport("")
		Expect(err).ToNot(HaveOccurred())
		Expect(transport).To(BeNil())
	})

	It("Should build a TLS transport trusting the provided CA alongside the system roots", func() {
		ca, err := (&secretsutils.CertificateSecretConfig{CommonName: "registry-ca", CertType: secretsutils.CACert}).GenerateCertificate()
		Expect(err).ToNot(HaveOccurred())

		dir := GinkgoT().TempDir()
		Expect(os.WriteFile(filepath.Join(dir, secretsutils.DataKeyCertificateBundle), ca.CertificatePEM, 0600)).To(Succeed())

		transport, err := utils.RegistryTransport(dir)
		Expect(err).ToNot(HaveOccurred())
		Expect(transport).ToNot(BeNil())

		httpTransport, ok := transport.(*http.Transport)
		Expect(ok).To(BeTrue())
		Expect(httpTransport.TLSClientConfig).ToNot(BeNil())
		Expect(httpTransport.TLSClientConfig.RootCAs).ToNot(BeNil())
		Expect(httpTransport.TLSClientConfig.MinVersion).To(Equal(uint16(tls.VersionTLS12)))
	})

	It("Should fail when the bundle file is missing", func() {
		transport, err := utils.RegistryTransport(GinkgoT().TempDir())
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("failed to read registry CA bundle"))
		Expect(transport).To(BeNil())
	})

	It("Should fail when the bundle contains no valid certificate", func() {
		dir := GinkgoT().TempDir()
		Expect(os.WriteFile(filepath.Join(dir, secretsutils.DataKeyCertificateBundle), []byte("not-a-pem-certificate"), 0600)).To(Succeed())

		transport, err := utils.RegistryTransport(dir)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("failed to append any certificate from registry CA bundle"))
		Expect(transport).To(BeNil())
	})
})
