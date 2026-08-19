// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package common

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	registryv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v3/pkg/oci/mutate"
	ociRemote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/cosign/v3/pkg/oci/signed"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
	"github.com/sigstore/sigstore/pkg/signature"
)

// GenerateKeyPair generates an ECDSA P-256 key pair and returns the private key together with its
// public key encoded as a PKIX PEM string (the format lakom expects in the cosign public-key config).
func GenerateKeyPair() (*ecdsa.PrivateKey, string, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}

	derBytes, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return nil, "", err
	}

	publicKeyPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}))

	return privateKey, publicKeyPEM, nil
}

// PushRandomImage pushes a randomly-generated OCI image to the given repository (e.g.
// "registry.local.gardener.cloud:5001/lakom-e2e-signed") and returns the built image together with
// its fully-qualified digest reference. The registry is treated as insecure (HTTP) to support the
// local landscape registry.
func PushRandomImage(repository string) (registryv1.Image, string, error) {
	img, err := random.Image(512, 1)
	if err != nil {
		return nil, "", err
	}

	tagRef, err := name.NewTag(repository+":latest", name.Insecure)
	if err != nil {
		return nil, "", err
	}

	if err := remote.Write(tagRef, img); err != nil {
		return nil, "", err
	}

	digest, err := img.Digest()
	if err != nil {
		return nil, "", err
	}

	return img, fmt.Sprintf("%s@%s", tagRef.Context().Name(), digest.String()), nil
}

// SignImage signs the given image at imageDigestRef with the provided private key and attaches the
// cosign signature next to the image in the registry. imageDigestRef must be a digest reference.
func SignImage(image registryv1.Image, imageDigestRef string, privateKey *ecdsa.PrivateKey) error {
	digest, err := name.NewDigest(imageDigestRef, name.Insecure)
	if err != nil {
		return err
	}

	signerVerifier, err := signature.LoadSignerVerifier(privateKey, crypto.SHA256)
	if err != nil {
		return err
	}

	payload, sig, err := signature.SignImage(signerVerifier, digest, nil)
	if err != nil {
		return err
	}

	ociSignature, err := static.NewSignature(payload, base64.StdEncoding.EncodeToString(sig))
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

// SignImageByRef signs an already-pushed image identified by imageRef (a tag or digest reference) with
// the provided private key. Unlike SignImage it does not require the built registryv1.Image object: it
// pulls the image from the registry, resolves it to its digest and signs that. Use this to sign images
// the test did not push itself (e.g. the extension's own lakom image, so it passes the runtime
// signature webhook).
func SignImageByRef(imageRef string, privateKey *ecdsa.PrivateKey) error {
	ref, err := name.ParseReference(imageRef, name.Insecure)
	if err != nil {
		return err
	}

	image, err := remote.Image(ref)
	if err != nil {
		return fmt.Errorf("failed to pull image %s: %w", imageRef, err)
	}

	digest, err := image.Digest()
	if err != nil {
		return fmt.Errorf("failed to compute digest for image %s: %w", imageRef, err)
	}

	// cosign signs the digest reference, regardless of whether imageRef was a tag or a digest.
	digestRef := fmt.Sprintf("%s@%s", ref.Context().Name(), digest.String())

	return SignImage(image, digestRef, privateKey)
}
