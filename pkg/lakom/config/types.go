// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package config

import "crypto"

// RSASchemeKey is key type alias for the RSA schemes.
type RSASchemeKey string

const (
	// RSAPKCS1v15 is the key for scheme "RSASSA-PKCS1-v1_5".
	RSAPKCS1v15 RSASchemeKey = "RSASSA-PKCS1-v1_5"
	// RSASSAPSS is the key for scheme "RSASSA-PSS".
	RSASSAPSS RSASchemeKey = "RSASSA-PSS"
)

// AlgorithmKey is key type alias for the algorithm.
type AlgorithmKey string

const (
	// RSAPKCS1v15SHA256 is the key for algorithm "RSASSA-PKCS1-v1_5-SHA256".
	RSAPKCS1v15SHA256 AlgorithmKey = "RSASSA-PKCS1-v1_5-SHA256"
	// RSAPKCS1v15SHA384 is the key for algorithm "RSASSA-PKCS1-v1_5-SHA384".
	RSAPKCS1v15SHA384 AlgorithmKey = "RSASSA-PKCS1-v1_5-SHA384"
	// RSAPKCS1v15SHA512 is the key for algorithm "RSASSA-PKCS1-v1_5-SHA512".
	RSAPKCS1v15SHA512 AlgorithmKey = "RSASSA-PKCS1-v1_5-SHA512"

	// RSASSAPSSSHA256 is the key for algorithm "RSASSA-PSS-SHA256".
	RSASSAPSSSHA256 AlgorithmKey = "RSASSA-PSS-SHA256"
	// RSASSAPSSSHA384 is the key for algorithm "RSASSA-PSS-SHA384".
	RSASSAPSSSHA384 AlgorithmKey = "RSASSA-PSS-SHA384"
	// RSASSAPSSSHA512 is the key for algorithm "RSASSA-PSS-SHA512".
	RSASSAPSSSHA512 AlgorithmKey = "RSASSA-PSS-SHA512"
)

// Config is the user facing structure of the configuration file.
// It contains list of keys.
type Config struct {
	PublicKeys []Key `json:"publicKeys"`
}

// Key contains a public crypto key used for signature verification.
// Attributes to the key are its name and the algorithm that should be
// used during signature verification.
type Key struct {
	// Name is a human readable name associated with the key.
	Name string `json:"name"`
	// Key is the public crypto key.
	Key string `json:"key"`
	// Algorithm describes how the signature verifier to be configured
	// with the given key.
	Algorithm AlgorithmKey `json:"algorithm,omitempty"`
}

// CompletedConfig is internal representation of the lakom coinfiguration.
type CompletedConfig struct {
	// Keys is list of keys and their attributes.
	Keys []VerifierKey
}

// VerifierKey contains a public crypto key used for signature verification.
// Attributes to the key are its name, optionally a hash function and RSA scheme
// that should be used during signature verification.
type VerifierKey struct {
	// Name is a human readable name associated with the key.
	Name string
	// Key is the public crypto key.
	Key crypto.PublicKey
	// Hash is the hash function that the verifier should use during signature verification.
	Hash *crypto.Hash
	// Scheme is the RSA scheme (if the key is of RSA type) the verifier to use during signature verification.
	Scheme *RSASchemeKey
}
