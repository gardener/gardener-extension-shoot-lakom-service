// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package resolvetag_test

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

	ociRemote "github.com/sigstore/cosign/v2/pkg/oci/remote"

	"github.com/google/go-containerregistry/pkg/registry"
	registryv1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/oci/mutate"
	"github.com/sigstore/cosign/v2/pkg/oci/signed"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
	"github.com/sigstore/sigstore/pkg/signature"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

var (
	// Fake registry properties
	registryURL *url.URL
	server      *httptest.Server

	signedImageFullRef   string
	unsignedImageFullRef string

	signedImageTagRef      string
	unsignedImageTagRef    string
	nonExistantImageTagRef string

	// Key for signing images in fake registry
	privateKey *ecdsa.PrivateKey

	// Public key in PEM format for verifying signatures in the fake registry
	publicKey string
)

const (
	signedImageTag   = "signed"
	unsignedImageTag = "unsigned"
)

func TestCMD(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "ResolveTag Suite")
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

	signedImage, signedImageRef, err := writeRandomImage(signedImageTag)
	Expect(err).ToNot(HaveOccurred())
	_, unsignedImageRef, err := writeRandomImage(unsignedImageTag)
	Expect(err).ToNot(HaveOccurred())

	signedImageFullRef = signedImageRef.Name()
	unsignedImageFullRef = unsignedImageRef.Name()

	signedImageTagRef = signedImageRef.Context().Tag(signedImageTag).String()
	unsignedImageTagRef = unsignedImageRef.Context().Tag(unsignedImageTag).String()

	nonExistantImageTagRef = fmt.Sprintf("%s:nonexistant", signedImageRef.Context().Name())

	privateKey, err = cosign.GeneratePrivateKey()
	Expect(err).ToNot(HaveOccurred())
	publicKey, err = publicKeyToPEM(privateKey.Public())
	Expect(err).ToNot(HaveOccurred())

	err = signImage(signedImage, signedImageFullRef)
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

func writeRandomImage(tag string) (registryv1.Image, name.Reference, error) {
	// Create image
	i, err := random.Image(512, 1)
	if err != nil {
		return nil, nil, err
	}

	// Create tag
	tagName := fmt.Sprintf("%s/%s:%s", registryURL.Host, "test", tag)
	tagRef, err := name.NewTag(tagName)
	if err != nil {
		return nil, nil, err
	}

	// Write image to registry
	err = remote.Write(tagRef, i)
	if err != nil {
		return nil, nil, err
	}

	// Get digest
	headResponse, err := remote.Head(tagRef)

	// TODO(rado): There should be an easier way than this
	fullRef := tagRef.Context().Name() + "@" + headResponse.Digest.String()

	reference, err := name.ParseReference(fullRef)
	if err != nil {
		return nil, nil, err
	}

	return i, reference, nil
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
