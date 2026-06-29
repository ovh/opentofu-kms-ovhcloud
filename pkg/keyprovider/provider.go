// SPDX-FileCopyrightText: 2026 OVH SAS <opensource@ovh.net>
//
// SPDX-License-Identifier: Apache-2.0

package keyprovider

import (
	"context"
	"crypto/tls"
	"fmt"

	"github.com/ovh/opentofu-kms-ovhcloud/pkg/config"
	"github.com/ovh/opentofu-kms-ovhcloud/pkg/utils"

	"github.com/google/uuid"
	"github.com/ovh/okms-sdk-go"
)

// encryptedKeyField is the key under which the wrapped data key is stored in the metadata.
const encryptedKeyField = "encrypted_key"

// okmsClient is the subset of the OVHcloud KMS client used by the key provider.
// It is defined as an interface so it can be mocked in tests.
type okmsClient interface {
	GenerateDataKey(ctx context.Context, okmsID, keyID uuid.UUID, name string, size int32) (plain []byte, encrypted string, err error)
	DecryptDataKey(ctx context.Context, okmsID, keyID uuid.UUID, encryptedKey string) ([]byte, error)
}

// newOkmsClient builds the real OVHcloud KMS client. It is a variable so tests can replace it.
var newOkmsClient = func(endpoint string, cfg okms.ClientConfig, token string) (okmsClient, error) {
	client, err := okms.NewRestAPIClient(endpoint, cfg)
	if err != nil {
		return nil, err
	}
	if token != "" {
		client.SetCustomHeader("Authorization", "Bearer "+token)
	}
	return client, nil
}

// KeyProvider generates and unwraps data keys using the OVHcloud KMS.
type KeyProvider struct {
	svc     okmsClient
	okmsID  uuid.UUID
	keyID   uuid.UUID
	keyName string
	keyBits int32
}

// New builds a KeyProvider from a validated configuration.
func New(cfg *config.Config) (*KeyProvider, error) {
	okmsID, err := uuid.Parse(cfg.Auth.OkmsID)
	if err != nil {
		return nil, fmt.Errorf("invalid okms id: %w", err)
	}
	keyID, err := uuid.Parse(cfg.KeyID)
	if err != nil {
		return nil, fmt.Errorf("invalid key id: %w", err)
	}

	client, err := newOkmsClient(cfg.Endpoint, buildClientConfig(cfg.TlsConfig), cfg.Auth.Token)
	if err != nil {
		return nil, fmt.Errorf("create okms client: %w", err)
	}

	return &KeyProvider{
		svc:     client,
		okmsID:  okmsID,
		keyID:   keyID,
		keyName: cfg.KeyName,
		keyBits: cfg.KeyBits,
	}, nil
}

func buildClientConfig(tlsConfig *tls.Config) okms.ClientConfig {
	return okms.ClientConfig{
		Timeout: utils.PtrTo(okms.DefaultHTTPClientTimeout),
		Retry: &okms.RetryConfig{
			RetryMax: 4,
		},
		TlsCfg: tlsConfig,
	}
}

// Provide implements the external key provider protocol step 3: it always generates a
// fresh encryption key (storing the wrapped form in the output metadata) and, when input
// metadata is present, unwraps the stored data key to produce the decryption key.
func (k *KeyProvider) Provide(ctx context.Context, in Input) (Output, error) {
	plainKey, encryptedKey, err := k.svc.GenerateDataKey(ctx, k.okmsID, k.keyID, k.keyName, k.keyBits)
	if err != nil {
		return Output{}, fmt.Errorf("failed to generate data key (okms_id=%s, key_id=%s): %w", k.okmsID, k.keyID, err)
	}

	out := Output{
		Keys: Keys{EncryptionKey: plainKey},
		Meta: Metadata{ExternalData: map[string]any{encryptedKeyField: encryptedKey}},
	}

	if in != nil {
		if raw, present := in.ExternalData[encryptedKeyField]; present {
			stored, ok := raw.(string)
			if !ok {
				return Output{}, fmt.Errorf("invalid input metadata: %q must be a string, got %T", encryptedKeyField, raw)
			}
			if stored != "" {
				decryptedKey, err := k.svc.DecryptDataKey(ctx, k.okmsID, k.keyID, stored)
				if err != nil {
					return Output{}, fmt.Errorf("failed to decrypt data key (okms_id=%s, key_id=%s): %w", k.okmsID, k.keyID, err)
				}
				out.Keys.DecryptionKey = decryptedKey
			}
		}
	}

	return out, nil
}
