// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"context"
	"sync"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/authn/k8schain"
	kauth "github.com/google/go-containerregistry/pkg/authn/kubernetes"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// lazyKeyChainReader is implementation of utils.KeyChainReader which ensures
// the image pull secrets of a pod are read only once for all containers
type lazyKeyChainReader struct {
	once           sync.Once
	keyChainReader func() (authn.Keychain, error)

	keyChain authn.Keychain
	err      error
}

func (k *lazyKeyChainReader) GetKeyChain() (authn.Keychain, error) {
	k.once.Do(func() {
		k.keyChain, k.err = k.keyChainReader()
	})

	return k.keyChain, k.err
}

// NewLazyKeyChainReader returns new lazyKeyChainReader.
func NewLazyKeyChainReader(reader func() (authn.Keychain, error)) *lazyKeyChainReader {
	return &lazyKeyChainReader{
		keyChainReader: reader,
	}
}

// NewLazyKeyChainReaderFromPod creates lazyKeyChainReader for given pod.
func NewLazyKeyChainReaderFromPod(ctx context.Context, c client.Reader, pod *corev1.Pod, useOnlyImagePullSecrets bool) *lazyKeyChainReader {
	return NewLazyKeyChainReader(
		func() (authn.Keychain, error) {
			var imagePullSecrets = make([]corev1.Secret, len(pod.Spec.ImagePullSecrets))
			for _, sn := range pod.Spec.ImagePullSecrets {
				secret := &corev1.Secret{}
				secretKey := client.ObjectKey{Namespace: pod.GetNamespace(), Name: sn.Name}

				if err := c.Get(ctx, secretKey, secret); err != nil {
					if apierrors.IsNotFound(err) {
						continue
					}
					return nil, err
				}
				imagePullSecrets = append(imagePullSecrets, *secret)
			}

			if useOnlyImagePullSecrets {
				return kauth.NewFromPullSecrets(ctx, imagePullSecrets)
			}

			return k8schain.NewFromPullSecrets(ctx, imagePullSecrets)
		},
	)
}
