// SPDX-FileCopyrightText: 2026 OVH SAS <opensource@ovh.net>
//
// SPDX-License-Identifier: Apache-2.0

package keyprovider

import (
	"context"
	"errors"

	"github.com/google/uuid"
)

// mockOkmsClient is a configurable in-memory implementation of okmsClient.
type mockOkmsClient struct {
	plain     []byte
	encrypted string
	decrypted []byte

	generateErr error
	decryptErr  error

	lastDecryptInput string
}

func (m *mockOkmsClient) GenerateDataKey(_ context.Context, _, _ uuid.UUID, _ string, _ int32) ([]byte, string, error) {
	if m.generateErr != nil {
		return nil, "", m.generateErr
	}
	return m.plain, m.encrypted, nil
}

func (m *mockOkmsClient) DecryptDataKey(_ context.Context, _, _ uuid.UUID, encryptedKey string) ([]byte, error) {
	m.lastDecryptInput = encryptedKey
	if m.decryptErr != nil {
		return nil, m.decryptErr
	}
	return m.decrypted, nil
}

var errBoom = errors.New("boom")
