//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This file was copied and modified from the sigstore/policy-controller project
// https://github.com/sigstore/policy-controller/blob/c0ba5b3bf3cd0ee928a5b7efdafdbc87a039888d/pkg/webhook/validation.go
// Modifications Copyright (c) 2022 SAP SE or an SAP affiliate company. All rights reserved.

package utils

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// GetCosignPublicKeys parses and returns all valid cosign public keys from byte array.
func GetCosignPublicKeys(rawData []byte) ([]crypto.PublicKey, error) {
	keys := []crypto.PublicKey{}

	pems := parsePems(rawData)
	for _, p := range pems {
		key, err := x509.ParsePKIXPublicKey(p.Bytes)
		if err != nil {
			return nil, err
		} else {
			keys = append(keys, key.(crypto.PublicKey))
		}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no valid keys were found")
	}
	return keys, nil
}

func parsePems(b []byte) []*pem.Block {
	p, rest := pem.Decode(b)
	if p == nil {
		return nil
	}
	pems := []*pem.Block{p}

	if rest != nil {
		return append(pems, parsePems(rest)...)
	}
	return pems
}
