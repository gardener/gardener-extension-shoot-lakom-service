// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package verifysignature_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	registryv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/oci/mutate"
	ociRemote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/cosign/v2/pkg/oci/signed"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
	"github.com/sigstore/sigstore/pkg/signature"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

var (
	scheme *runtime.Scheme

	// Fake registry properties
	registryURL *url.URL
	server      *httptest.Server

	signedImageTag    string
	nonSignedImageTag string

	// Key for signing images in fake registry
	privateKey *ecdsa.PrivateKey

	// Public key in PEM format for verifying signatures in the fake registry
	publicKey string
)

func TestCMD(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "VerifySignature Suite")
}

var _ = BeforeSuite(func() {
	scheme = runtime.NewScheme()
	err := corev1.AddToScheme(scheme)
	Expect(err).ToNot(HaveOccurred())

	dirPath, err := os.MkdirTemp("", "verifysignature_test")
	Expect(err).ToNot(HaveOccurred())
	DeferCleanup(func() {
		err := os.RemoveAll(dirPath)
		Expect(err).ToNot(HaveOccurred())
	})

	// Tests rely on a fake registry
	registryURL, server = startFakeRegistry()
	DeferCleanup(func() {
		server.Close()
	})

	var signedImage registryv1.Image
	signedImage, signedImageTag, err = writeRandomImage()
	Expect(err).ToNot(HaveOccurred())
	_, nonSignedImageTag, err = writeRandomImage()
	Expect(err).ToNot(HaveOccurred())

	privateKey, err = cosign.GeneratePrivateKey()
	Expect(err).ToNot(HaveOccurred())
	publicKey, err = publicKeyToPEM(privateKey.Public())
	Expect(err).ToNot(HaveOccurred())

	err = signImage(signedImage, signedImageTag)
	Expect(err).ToNot(HaveOccurred())
})

var _ = AfterSuite(func() {
	server.Close()
})

func startFakeRegistry() (*url.URL, *httptest.Server) {
	nopLog := log.New(io.Discard, "", 0)
	s := httptest.NewServer(registry.New(registry.Logger(nopLog)))
	u, err := url.Parse(s.URL)
	if err != nil {
		log.Fatal("Error parsing")
	}

	return u, s
}

func publicKeyToPEM(pub crypto.PublicKey) (string, error) {
	// Marshal the public key to DER format
	derBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}

	// Create a PEM block
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}

	// Encode the PEM block to a string
	var pemBytes []byte
	pemBytes = pem.EncodeToMemory(pemBlock)

	return string(pemBytes), nil
}

func writeRandomImage() (registryv1.Image, string, error) {
	// Create image
	i, err := random.Image(512, 1)
	if err != nil {
		return nil, "", err
	}

	// Create tag
	tagName := fmt.Sprintf("%s/%s:v0.1", registryURL.Host, "test")
	tag, err := name.NewTag(tagName)
	if err != nil {
		return nil, "", err
	}

	// Write image to registry
	err = remote.Write(tag, i)
	if err != nil {
		return nil, "", err
	}

	// Get digest
	headResponse, err := remote.Head(tag)

	// TODO(rado): There should be an easier way than this
	fullRef := tag.Context().Name() + "@" + headResponse.Digest.String()

	return i, fullRef, nil
}

func signImage(image registryv1.Image, imageFullRef string) error {
	digest, err := name.NewDigest(imageFullRef)
	if err != nil {
		return err
	}

	signerVerifier, err := signature.LoadSignerVerifier(privateKey, crypto.SHA256)
	if err != nil {
		return err
	}

	payload, signature, err := signature.SignImage(signerVerifier, digest, nil)
	if err != nil {
		return err
	}

	ociSignature, err := static.NewSignature(payload, base64.StdEncoding.EncodeToString(signature))
	if err != nil {
		return err
	}

	si := signed.Image(image)
	si, err = mutate.AttachSignatureToImage(si, ociSignature)
	if err != nil {
		return err
	}

	err = ociRemote.WriteSignatures(digest.Context(), si)
	if err != nil {
		return err
	}

	return nil
}
