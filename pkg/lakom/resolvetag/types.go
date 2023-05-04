// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package resolvetag

import (
	"context"

	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/lakom/utils"

	"github.com/google/go-containerregistry/pkg/name"
)

// Resolver is interface which implementations should resolve image tags to digests.
type Resolver interface {
	Resolve(context.Context, name.Tag, utils.KeyChainReader) (string, error)
}

// DigestCache is interface which implementations should store mapping of image tags to digests.
type DigestCache interface {
	GetDigest(string) (string, bool)
	StoreDigest(string, string)
}
