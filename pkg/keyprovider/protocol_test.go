// SPDX-FileCopyrightText: 2026 OVH SAS <opensource@ovh.net>
//
// SPDX-License-Identifier: Apache-2.0

package keyprovider

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHeaderEncoding(t *testing.T) {
	data, err := json.Marshal(Header{Magic: HeaderMagic, Version: ProtocolVersion})
	require.NoError(t, err)

	// OpenTofu matches this header byte-for-byte to recognize the external provider.
	assert.JSONEq(t, `{"magic":"OpenTofu-External-Key-Provider","version":1}`, string(data))
}

func TestInputNullUnmarshalsToNil(t *testing.T) {
	var in Input
	require.NoError(t, json.Unmarshal([]byte("null"), &in))
	assert.Nil(t, in)
}

func TestInputMetadataUnmarshal(t *testing.T) {
	var in Input
	require.NoError(t, json.Unmarshal([]byte(`{"external_data":{"encrypted_key":"abc"}}`), &in))
	require.NotNil(t, in)
	assert.Equal(t, "abc", in.ExternalData["encrypted_key"])
}

func TestOutputEncoding(t *testing.T) {
	out := Output{
		Keys: Keys{
			EncryptionKey: []byte{1, 2, 3, 4},
			DecryptionKey: []byte{5, 6, 7, 8},
		},
		Meta: Metadata{ExternalData: map[string]any{encryptedKeyField: "wrapped"}},
	}
	data, err := json.Marshal(out)
	require.NoError(t, err)

	// []byte fields are base64-encoded; top-level keys are "keys" and "meta".
	assert.JSONEq(t,
		`{"keys":{"encryption_key":"AQIDBA==","decryption_key":"BQYHCA=="},"meta":{"external_data":{"encrypted_key":"wrapped"}}}`,
		string(data))
}
