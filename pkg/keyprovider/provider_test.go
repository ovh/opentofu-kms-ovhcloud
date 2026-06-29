// SPDX-FileCopyrightText: 2026 OVH SAS <opensource@ovh.net>
//
// SPDX-License-Identifier: Apache-2.0

package keyprovider

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestProvider(svc okmsClient) *KeyProvider {
	return &KeyProvider{
		svc:     svc,
		okmsID:  uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		keyID:   uuid.MustParse("00000000-0000-0000-0000-000000000000"),
		keyName: "test-key",
		keyBits: 256,
	}
}

func TestProvideEncryptOnly(t *testing.T) {
	svc := &mockOkmsClient{
		plain:     []byte("0123456789abcdef0123456789abcdef"),
		encrypted: "wrapped-data-key",
	}
	kp := newTestProvider(svc)

	out, err := kp.Provide(context.Background(), nil)
	require.NoError(t, err)

	assert.Equal(t, svc.plain, out.Keys.EncryptionKey)
	assert.Nil(t, out.Keys.DecryptionKey)
	assert.Equal(t, "wrapped-data-key", out.Meta.ExternalData[encryptedKeyField])
	assert.Empty(t, svc.lastDecryptInput, "DecryptDataKey must not be called when encrypting only")
}

func TestProvideEncryptAndDecrypt(t *testing.T) {
	svc := &mockOkmsClient{
		plain:     []byte("0123456789abcdef0123456789abcdef"),
		encrypted: "new-wrapped-data-key",
		decrypted: []byte("decrypted-key-material-32-bytes!"),
	}
	kp := newTestProvider(svc)

	in := &Metadata{ExternalData: map[string]any{encryptedKeyField: "old-wrapped-data-key"}}

	out, err := kp.Provide(context.Background(), in)
	require.NoError(t, err)

	assert.Equal(t, svc.plain, out.Keys.EncryptionKey)
	assert.Equal(t, svc.decrypted, out.Keys.DecryptionKey)
	assert.Equal(t, "new-wrapped-data-key", out.Meta.ExternalData[encryptedKeyField])
	assert.Equal(t, "old-wrapped-data-key", svc.lastDecryptInput, "the stored wrapped key must be unwrapped")
}

func TestProvideMetadataWithoutEncryptedKey(t *testing.T) {
	svc := &mockOkmsClient{plain: []byte("key"), encrypted: "wrapped"}
	kp := newTestProvider(svc)

	// Input metadata present but missing the encrypted_key entry: no decryption key expected.
	in := &Metadata{ExternalData: map[string]any{"unrelated": "value"}}

	out, err := kp.Provide(context.Background(), in)
	require.NoError(t, err)
	assert.Nil(t, out.Keys.DecryptionKey)
	assert.Empty(t, svc.lastDecryptInput)
}

func TestProvideMetadataWithNonStringEncryptedKey(t *testing.T) {
	svc := &mockOkmsClient{plain: []byte("key"), encrypted: "wrapped"}
	kp := newTestProvider(svc)

	in := &Metadata{ExternalData: map[string]any{encryptedKeyField: 42}}

	_, err := kp.Provide(context.Background(), in)
	require.Error(t, err)
	assert.ErrorContains(t, err, encryptedKeyField)
	assert.Empty(t, svc.lastDecryptInput, "DecryptDataKey must not be called for corrupt metadata")
}

func TestProvideGenerateError(t *testing.T) {
	kp := newTestProvider(&mockOkmsClient{generateErr: errBoom})

	_, err := kp.Provide(context.Background(), nil)
	assert.ErrorIs(t, err, errBoom)
}

func TestProvideDecryptError(t *testing.T) {
	svc := &mockOkmsClient{plain: []byte("key"), encrypted: "wrapped", decryptErr: errBoom}
	kp := newTestProvider(svc)

	in := &Metadata{ExternalData: map[string]any{encryptedKeyField: "old-wrapped"}}

	_, err := kp.Provide(context.Background(), in)
	assert.ErrorIs(t, err, errBoom)
}
