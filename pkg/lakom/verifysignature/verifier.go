// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package verifysignature

import (
	"context"
	"crypto"
	"errors"
	"fmt"

	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/constants"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/lakom/metrics"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/lakom/utils"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/sigstore/pkg/signature"
	"golang.org/x/sync/singleflight"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

type directVerifier struct {
	publicKeys []crypto.PublicKey
}

// NewDirectVerifier creates new verifier and returns it.
func NewDirectVerifier(keys []crypto.PublicKey) *directVerifier {
	dv := &directVerifier{
		publicKeys: keys,
	}
	return dv
}

// Verify check if image is signed by at least one of the configured cosign public keys.
func (r *directVerifier) Verify(ctx context.Context, image string, kcr utils.KeyChainReader) (bool, error) {
	imageRef, err := name.ParseReference(image)
	if err != nil {
		return false, err
	}

	keyChain, err := kcr.GetKeyChain()
	if err != nil {
		return false, err
	}

	remoteOpts := ociremote.WithRemoteOptions(
		remote.WithContext(ctx),
		remote.WithUserAgent(constants.ApplicationName),
		remote.WithAuthFromKeychain(keyChain),
	)

	return verify(ctx, imageRef, r.publicKeys, remoteOpts)
}

func verify(ctx context.Context, imageRef name.Reference, keys []crypto.PublicKey, opts ...ociremote.Option) (bool, error) {
	if _, ok := imageRef.(name.Digest); !ok {
		return false, fmt.Errorf("image reference is not a digest, reference: %q", imageRef.Name())
	}

	logger := logf.FromContext(ctx)

	// We need successful verification for at least one key, therefore any other failures can be ignored.
	for idx, k := range keys {
		log := logger.WithValues("cosignKeyID", idx)

		verifier, err := signature.LoadVerifier(k, crypto.SHA256)
		if err != nil {
			log.Info("Failed creating verifier", "error", err.Error())
			continue
		}

		checkedSignatures, _, err := cosign.VerifyImageSignatures(ctx, imageRef, &cosign.CheckOpts{
			RegistryClientOpts: opts,
			SigVerifier:        verifier,
			ClaimVerifier:      cosign.SimpleClaimVerifier,
			IgnoreSCT:          true,
			IgnoreTlog:         true,
		})
		if err != nil {
			if IsNoSignaturesFound(err) {
				log.Info("No signatures found for the image", "error", err.Error())
				return false, nil
			}

			if IsNoMatchingSignatures(err) {
				if errors.Is(ctx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
					// Mitigation for https://github.com/gardener/gardener-extension-shoot-lakom-service/issues/25
					// TODO(vpnachev): remove when https://github.com/sigstore/cosign/issues/3133 is fixed and vendored
					log.Info("No matching signatures error detected as canceled or deadline exceeded context", "error", err)
					return false, err
				}

				log.Info("No matching signatures found for current public key", "error", err.Error())
				continue
			}

			return false, err
		}

		if len(checkedSignatures) == 0 {
			// the cosign library is returning an error if the checkedSignatures are 0
			// but this can changed in a future version and break us
			log.Info("Found no valid signatures")
			continue
		}

		log.Info("Image signature successfully verified")
		return true, nil
	}

	logger.Info("Image signature verification failed for all configured keys")
	return false, nil
}

type cacheVerifier struct {
	cache          SignatureVerificationResultCache
	actualVerifier Verifier
	requestGroup   singleflight.Group
}

// NewCacheVerifier creates cached verifier from the provided cache and verifier.
func NewCacheVerifier(cache SignatureVerificationResultCache, verifier Verifier) *cacheVerifier {
	cv := &cacheVerifier{
		cache:          cache,
		actualVerifier: verifier,
	}
	return cv
}

// Verify check cosign signature of an image. Firstly it checks if the cache have an entry
// for the verification state of the image and returns it. If the cache have no entry,
// it uses the verifier to do the real verification, persists the result in the cache and return it.
func (r *cacheVerifier) Verify(ctx context.Context, image string, kcr utils.KeyChainReader) (bool, error) {
	verified, found := r.cache.GetSignatureVerificationResult(image)
	if found {
		metrics.ImageSignatureCache.WithLabelValues(metrics.CacheHit).Inc()
		return verified, nil
	}

	defer r.requestGroup.Forget(image)
	v, err, _ := r.requestGroup.Do(image, func() (any, error) {
		verified, err := r.actualVerifier.Verify(ctx, image, kcr)
		if err != nil {
			return false, err
		}
		return verified, nil
	})
	if err != nil {
		return false, err
	}

	// Casting is safe here
	verified = v.(bool)
	metrics.ImageSignatureCache.WithLabelValues(metrics.CacheMiss).Inc()
	r.cache.StoreSignatureVerificationResult(image, verified)
	return verified, nil
}

// IsNoMatchingSignatures checks if error is of type
// [cosign.ErrNoMatchingSignatures].
func IsNoMatchingSignatures(err error) bool {
	var t *cosign.ErrNoMatchingSignatures
	return errors.As(err, &t)
}

// IsNoSignaturesFound checks if error is of type
// [cosign.ErrNoSignaturesFound].
func IsNoSignaturesFound(err error) bool {
	var t *cosign.ErrNoSignaturesFound
	return errors.As(err, &t)
}
