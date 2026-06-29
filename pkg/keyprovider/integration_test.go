// SPDX-FileCopyrightText: 2026 OVH SAS <opensource@ovh.net>
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package keyprovider

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ovh/opentofu-kms-ovhcloud/pkg/config"
)

/*
The following environment variable must be set:
KMS_KEY_ID - UUID of an existing symmetric service key on the target KMS instance.

Credentials are loaded from the standard configuration (environment variables or ~/.ovh-kms/okms.yaml). With mTLS authentication, set:
KMS_RESTAPI_ENDPOINT - OKMS HTTP endpoint
KMS_RESTAPI_CERT     - path to the client certificate
KMS_RESTAPI_KEY      - path to the client private key
KMS_RESTAPI_CA       - path to a custom CA bundle (optional)
*/

func TestMain(m *testing.M) {
	if os.Getenv("KMS_KEY_ID") == "" {
		panic("KMS_KEY_ID must be set")
	}
	os.Exit(m.Run())
}

func newIntegrationProvider(t *testing.T) *KeyProvider {
	t.Helper()

	cfg, err := config.NewConfig(nil)
	require.NoError(t, err, "failed to load KMS configuration")

	kp, err := New(cfg)
	require.NoError(t, err, "failed to create key provider")

	return kp
}

func TestIntegrationProvideEncryptOnly(t *testing.T) {
	kp := newIntegrationProvider(t)

	out, err := kp.Provide(context.Background(), nil)
	require.NoError(t, err)

	assert.NotEmpty(t, out.Keys.EncryptionKey)
	assert.Empty(t, out.Keys.DecryptionKey)
	require.NotNil(t, out.Meta.ExternalData)
	assert.NotEmpty(t, out.Meta.ExternalData[encryptedKeyField])
}

func TestIntegrationProvideRoundTrip(t *testing.T) {
	kp := newIntegrationProvider(t)

	first, err := kp.Provide(context.Background(), nil)
	require.NoError(t, err)
	require.NotEmpty(t, first.Keys.EncryptionKey)

	second, err := kp.Provide(context.Background(), Input(&first.Meta))
	require.NoError(t, err)

	assert.Equal(t, first.Keys.EncryptionKey, second.Keys.DecryptionKey, "wrapped key must unwrap to the original plaintext data key")
}
