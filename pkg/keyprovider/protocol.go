// SPDX-FileCopyrightText: 2026 OVH SAS <opensource@ovh.net>
//
// SPDX-License-Identifier: Apache-2.0

// Package keyprovider implements the OpenTofu external key provider protocol
// (https://opentofu.org/docs/language/state/encryption/#writing-an-external-key-provider)
// backed by the OVHcloud Key Management Service.
package keyprovider

// HeaderMagic is the magic string identifying the program as an OpenTofu external
// key provider. It must be written verbatim, note the hyphen in "Key-Provider".
const HeaderMagic = "OpenTofu-External-Key-Provider"

// ProtocolVersion is the only protocol version currently supported.
const ProtocolVersion = 1

// Header is the single-line greeting the key provider writes to stdout first.
type Header struct {
	Magic   string `json:"magic"`
	Version int    `json:"version"`
}

// Metadata describes both the input and output metadata. It is stored alongside
// the encrypted data and passed back as input on the next decryption run.
type Metadata struct {
	ExternalData map[string]any `json:"external_data"`
}

// Input is the data OpenTofu writes to stdin. It is nil ("null") when only an
// encryption key is required, or the previously stored metadata when decrypting.
type Input *Metadata

// Keys holds the produced key material.
type Keys struct {
	// EncryptionKey must always be provided. As a []byte it is marshaled to base64.
	EncryptionKey []byte `json:"encryption_key,omitempty"`
	// DecryptionKey is only provided when input metadata was present.
	DecryptionKey []byte `json:"decryption_key,omitempty"`
}

// Output is the data structure written to stdout.
type Output struct {
	Keys Keys     `json:"keys"`
	Meta Metadata `json:"meta"`
}
