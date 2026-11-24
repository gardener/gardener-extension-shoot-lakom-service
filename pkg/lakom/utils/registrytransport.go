// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	secretsutils "github.com/gardener/gardener/pkg/utils/secrets"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// RegistryTransport builds an HTTP transport whose TLS trust pool contains the public system root
// CAs plus the private registry CA bundle found in caDir.
func RegistryTransport(caDir string) (http.RoundTripper, error) {
	if caDir == "" {
		return nil, nil
	}

	caPath := filepath.Join(caDir, secretsutils.DataKeyCertificateBundle)
	caBundle, err := os.ReadFile(caPath) // #nosec G304 -- caDir is an operator-controlled flag pointing at a mounted ConfigMap.
	if err != nil {
		return nil, fmt.Errorf("failed to read registry CA bundle %q: %w", caPath, err)
	}

	// Start from the public system roots so public registries remain trusted, then add the private CA.
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(caBundle) {
		return nil, fmt.Errorf("failed to append any certificate from registry CA bundle %q", caPath)
	}

	transport := remote.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}
	return transport, nil
}
