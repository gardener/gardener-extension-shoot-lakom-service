// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/lakom/utils"

	"k8s.io/utils/ptr"
	"sigs.k8s.io/yaml"
)

// LoadConfig reads and validates lakom configuration from given file path.
func LoadConfig(filename string) (*Config, error) {
	rawConfig, err := os.ReadFile(filepath.Clean(filename))
	if err != nil {
		return nil, fmt.Errorf("failed to read config file, %w", err)
	}

	c := &Config{}
	if err := yaml.Unmarshal(rawConfig, c); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config, %w", err)
	}

	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("failed to validate config, %w", err)
	}

	return c, nil
}

func (c *Config) validate() error {
	usedNames := map[string]any{}

	for idx, k := range c.PublicKeys {
		if k.Name == "" {
			return fmt.Errorf("key at index %d has empty name", idx)
		}

		if _, ok := usedNames[k.Name]; ok {
			return fmt.Errorf("duplicated key name %q at index %d", k.Name, idx)
		}
		usedNames[k.Name] = nil

		if keys, err := utils.GetCosignPublicKeys([]byte(k.Key)); err != nil {
			return fmt.Errorf("failed to parse public key for %q (index %d): %w", k.Name, idx, err)
		} else if len(keys) != 1 {
			return fmt.Errorf("expected to find exactly one public key, but found %d keys for key name %q (index %d)", len(keys), k.Name, idx)
		}
	}

	return nil
}

// Complete transforms the user exposed config to the internal representation of the config.
func (c *Config) Complete() (*CompletedConfig, error) {
	res := CompletedConfig{
		Keys: []VerifierKey{},
	}

	for idx, k := range c.PublicKeys {
		config := VerifierKey{
			Name: k.Name,
		}

		keys, err := utils.GetCosignPublicKeys([]byte(k.Key))
		if err != nil {
			return nil, err
		}

		config.Key = keys[0]
		hash, scheme, err := parseAlgorithm(config.Key, k.Algorithm)
		if err != nil {
			return nil, fmt.Errorf("failed to parse algorithm for key %q(%d), %w", config.Name, idx, err)
		}

		config.Hash = hash
		config.RSAScheme = scheme

		res.Keys = append(res.Keys, config)
	}

	res.Keys = uniqueKeys(res.Keys)

	return &res, nil
}

// uniqueKeys returns the unique set of [VerifierKey] items.
func uniqueKeys(keys []VerifierKey) []VerifierKey {
	result := make([]VerifierKey, 0)

	for _, item := range keys {
		// Equality check between the keys is achieved via the 'Equal'
		// function that we know is implemented for every public key type.
		// Ref: https://pkg.go.dev/crypto#PublicKey
		// We cast to the interface to inform the compiler of the func.
		key, ok := item.Key.(interface{ Equal(x crypto.PublicKey) bool })
		if !ok {
			continue
		}

		predicate := func(other VerifierKey) bool {
			return key.Equal(other.Key) &&
				*item.Hash == *other.Hash &&
				((item.RSAScheme == nil && other.RSAScheme == nil) ||
					(item.RSAScheme != nil && other.RSAScheme != nil && *item.RSAScheme == *other.RSAScheme))
		}
		if !slices.ContainsFunc(result, predicate) {
			result = append(result, item)
		}
	}

	return result
}

func parseAlgorithm(key crypto.PublicKey, algorithm AlgorithmKey) (*crypto.Hash, *RSASchemeKey, error) {
	defaultHash := crypto.SHA256

	switch key.(type) {
	case *rsa.PublicKey:
		return parseRSAAlgorithm(algorithm)
	default:
		return &defaultHash, nil, nil
	}
}

func parseRSAAlgorithm(algorithm AlgorithmKey) (*crypto.Hash, *RSASchemeKey, error) {
	switch algorithm {
	case "":
		// RSASSA-PKCS1-v1_5-SHA256 is the default algorithm
		fallthrough

	// RSASSA-PKCS1-v1_5
	case RSAPKCS1v15SHA256:
		return ptr.To(crypto.SHA256), ptr.To(RSAPKCS1v15), nil
	case RSAPKCS1v15SHA384:
		return ptr.To(crypto.SHA384), ptr.To(RSAPKCS1v15), nil
	case RSAPKCS1v15SHA512:
		return ptr.To(crypto.SHA512), ptr.To(RSAPKCS1v15), nil

	// RSASSA-PSS
	case RSASSAPSSSHA256:
		return ptr.To(crypto.SHA256), ptr.To(RSASSAPSS), nil
	case RSASSAPSSSHA384:
		return ptr.To(crypto.SHA384), ptr.To(RSASSAPSS), nil
	case RSASSAPSSSHA512:
		return ptr.To(crypto.SHA512), ptr.To(RSASSAPSS), nil

	default:
		return nil, nil, fmt.Errorf("rsa: unsupported algorithm %q", algorithm)
	}
}
