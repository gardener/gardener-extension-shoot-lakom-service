// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package resolvetag_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	mockclient "github.com/gardener/gardener/third_party/mock/controller-runtime/client"
	mockmanager "github.com/gardener/gardener/third_party/mock/controller-runtime/manager"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	registryv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sigstore/cosign/v3/pkg/oci/mutate"
	ociRemote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/cosign/v3/pkg/oci/signed"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
	"github.com/sigstore/sigstore/pkg/signature"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

var (
	// FullRef use the digest instead of the tag.
	signedImageDigestRef   string
	unsignedImageDigestRef string

	// TagRef use the tag instead of the digest for referencing the artifact.
	signedImageTagRef      string
	unsignedImageTagRef    string
	nonExistentImageTagRef string

	scheme    *runtime.Scheme
	ctrl      *gomock.Controller
	mgr       *mockmanager.MockManager
	apiReader *mockclient.MockReader
)

const (
	signedImageTag   = "signed"
	unsignedImageTag = "unsigned"
)

func TestResolveTagSuite(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "ResolveTag Suite")
}

var _ = BeforeSuite(func() {
	scheme = runtime.NewScheme()
	Expect(corev1.AddToScheme(scheme)).To(Succeed())

	dirPath, err := os.MkdirTemp("", "resolvetag_test")
	Expect(err).ToNot(HaveOccurred())
	DeferCleanup(func() {
		Expect(os.RemoveAll(dirPath)).To(Succeed())
	})

	// Tests rely on a fake registry
	registryURL, server := startRegistry()
	DeferCleanup(func() {
		server.Close()
	})

	signedImage, signedImageRef, err := createTestImage(registryURL, signedImageTag)
	Expect(err).ToNot(HaveOccurred())
	_, unsignedImageRef, err := createTestImage(registryURL, unsignedImageTag)
	Expect(err).ToNot(HaveOccurred())

	signedImageDigestRef = signedImageRef.Name()
	unsignedImageDigestRef = unsignedImageRef.Name()

	signedImageTagRef = signedImageRef.Context().Tag(signedImageTag).String()
	unsignedImageTagRef = unsignedImageRef.Context().Tag(unsignedImageTag).String()

	nonExistentImageTagRef = fmt.Sprintf("%s:nonexistant", signedImageRef.Context().Name())

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).ToNot(HaveOccurred())

	Expect(signImage(signedImage, signedImageDigestRef, privateKey)).To(Succeed())
})

func startRegistry() (*url.URL, *httptest.Server) {
	ginkgoLogger := log.New(GinkgoWriter, "", 0)
	s := httptest.NewServer(registry.New(registry.Logger(ginkgoLogger)))
	u, err := url.Parse(s.URL)
	Expect(err).ToNot(HaveOccurred())

	return u, s
}

func createTestImage(registryURL *url.URL, tag string) (registryv1.Image, name.Reference, error) {
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
	if err = remote.Write(tagRef, i); err != nil {
		return nil, nil, err
	}

	// Get digest
	headResponse, err := remote.Head(tagRef)
	if err != nil {
		return nil, nil, err
	}

	fullRef := tagRef.Context().Name() + "@" + headResponse.Digest.String()

	reference, err := name.ParseReference(fullRef)
	if err != nil {
		return nil, nil, err
	}

	return i, reference, nil
}

func signImage(image registryv1.Image, imageFullRef string, privateKey *ecdsa.PrivateKey) error {
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

	return ociRemote.WriteSignatures(digest.Context(), si)
}
