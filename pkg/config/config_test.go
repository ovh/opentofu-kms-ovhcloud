// SPDX-FileCopyrightText: 2026 OVH SAS <opensource@ovh.net>
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ovh/opentofu-kms-ovhcloud/pkg/testutils"

	"github.com/knadh/koanf/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	expectedEndpoint = "https://kms.example.com"
	expectedID       = "11111111-1111-1111-1111-111111111111"
	expectedToken    = "token"
	expectedKeyID    = "00000000-0000-0000-0000-000000000000"
)

// clearKMSEnv neutralizes any ambient KMS_* environment variables so the test controls its own
// environment and is not influenced by the caller's (e.g. when running `make integration-test`
// with real credentials exported). Values are restored when the test finishes.
func clearKMSEnv(t *testing.T) {
	t.Helper()

	for _, env := range os.Environ() {
		if key, _, found := strings.Cut(env, "="); found && strings.HasPrefix(key, envPrefix) {
			t.Setenv(key, "")
		}
	}
}

func copyTestConfig(t *testing.T, filename string) string {
	t.Helper()

	tempDir := t.TempDir()
	configDir := filepath.Join(tempDir, ".ovh-kms")
	require.NoError(t, os.Mkdir(configDir, 0o0755))

	content, err := os.ReadFile(filepath.Join("testdata", filename))
	require.NoError(t, err)

	configFile := filepath.Join(configDir, "okms.yaml")
	require.NoError(t, os.WriteFile(configFile, content, 0o0644))
	return tempDir
}

func TestLoadEnvConfig(t *testing.T) {
	k := koanf.New(".")

	t.Setenv("KMS_RESTAPI_ENDPOINT", expectedEndpoint)
	t.Setenv("KMS_RESTAPI_TYPE", "token")
	t.Setenv("KMS_RESTAPI_OKMSID", expectedID)
	t.Setenv("KMS_RESTAPI_TOKEN", expectedToken)
	t.Setenv("KMS_KEY_ID", expectedKeyID)

	err := loadEnvConfig(k, defaultProfile)
	require.NoError(t, err)

	base := "profiles." + defaultProfile + ".restapi."
	assert.Equal(t, expectedEndpoint, k.String(base+"endpoint"))
	assert.Equal(t, "token", k.String(base+"auth.type"))
	assert.Equal(t, expectedID, k.String(base+"auth.okmsId"))
	assert.Equal(t, expectedToken, k.String(base+"auth.token"))
	assert.Empty(t, k.String(base+"keyid"))
}

func TestLoadFileConfig(t *testing.T) {
	k := koanf.New(".")

	t.Setenv("HOME", copyTestConfig(t, "valid_mtls_config.yaml"))

	err := loadConfigFile(k)
	require.NoError(t, err)

	profile := k.String("profile")
	assert.Equal(t, "default", profile)

	base := "profiles.default.restapi"
	assert.Equal(t, "https://myserver.acme.com", k.String(base+".endpoint"))
	assert.Equal(t, "/path/to/public-ca.crt", k.String(base+".ca"))
	assert.Equal(t, "/path/to/domain/cert.pem", k.String(base+".auth.cert"))
	assert.Equal(t, "/path/to/domain/key.pem", k.String(base+".auth.key"))
}

func TestNewConfig(t *testing.T) {
	clearKMSEnv(t)

	t.Run("invalid mtls config", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("HOME", copyTestConfig(t, "valid_mtls_config.yaml"))
		tc, err := testutils.GenerateTestCert("ecdsa")
		require.NoError(t, err)

		certPath := testutils.WriteDataToTempFile(t, dir, "cert.pem", []byte("invalid"))
		keyPath := testutils.WriteDataToTempFile(t, dir, "key.pem", tc.KeyPEM)
		caPath := testutils.WriteDataToTempFile(t, dir, "ca.pem", tc.CertPEM)

		t.Setenv("KMS_RESTAPI_ENDPOINT", expectedEndpoint)
		t.Setenv("KMS_RESTAPI_CA", caPath)
		t.Setenv("KMS_RESTAPI_CERT", certPath)
		t.Setenv("KMS_RESTAPI_KEY", keyPath)

		_, err = NewConfig([]string{"--key-id", expectedKeyID})
		assert.Error(t, err)
	})

	t.Run("valid mtls config (okms id from cert)", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("HOME", t.TempDir()) // no config file; everything via KMS_*
		tc, err := testutils.GenerateTestCert("ecdsa", testutils.WithOkmsID(expectedID))
		require.NoError(t, err)

		certPath := testutils.WriteDataToTempFile(t, dir, "cert.pem", tc.CertPEM)
		keyPath := testutils.WriteDataToTempFile(t, dir, "key.pem", tc.KeyPEM)

		// key id supplied via env (the flag default), exercising the env fallback path.
		t.Setenv("KMS_RESTAPI_ENDPOINT", expectedEndpoint)
		t.Setenv("KMS_KEY_ID", expectedKeyID)
		t.Setenv("KMS_RESTAPI_CERT", certPath)
		t.Setenv("KMS_RESTAPI_KEY", keyPath)

		cfg, err := NewConfig(nil)
		require.NoError(t, err)

		assert.Equal(t, expectedKeyID, cfg.KeyID)
		assert.Equal(t, expectedID, cfg.Auth.OkmsID, "okms id must be extracted from the client certificate")
		require.NotNil(t, cfg.TlsConfig)
		assert.Len(t, cfg.TlsConfig.Certificates, 1)
	})

	t.Run("missing key_id", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir()) // no config file
		t.Setenv("KMS_RESTAPI_ENDPOINT", expectedEndpoint)
		t.Setenv("KMS_RESTAPI_TYPE", "token")
		t.Setenv("KMS_RESTAPI_OKMSID", expectedID)
		t.Setenv("KMS_RESTAPI_TOKEN", expectedToken)

		_, err := NewConfig(nil)
		assert.ErrorContains(t, err, "key_id")
	})

	t.Run("invalid key_bits", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		t.Setenv("KMS_RESTAPI_ENDPOINT", expectedEndpoint)
		t.Setenv("KMS_KEY_ID", expectedKeyID)
		t.Setenv("KMS_KEY_BITS", "100")
		t.Setenv("KMS_RESTAPI_TYPE", "token")
		t.Setenv("KMS_RESTAPI_OKMSID", expectedID)
		t.Setenv("KMS_RESTAPI_TOKEN", expectedToken)

		_, err := NewConfig(nil)
		assert.ErrorContains(t, err, "key_bits")
	})

	t.Run("invalid okms id", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		t.Setenv("KMS_RESTAPI_ENDPOINT", expectedEndpoint)
		t.Setenv("KMS_KEY_ID", expectedKeyID)
		t.Setenv("KMS_RESTAPI_TYPE", "token")
		t.Setenv("KMS_RESTAPI_OKMSID", "not-a-uuid")
		t.Setenv("KMS_RESTAPI_TOKEN", expectedToken)

		_, err := NewConfig(nil)
		assert.ErrorContains(t, err, "okms id")
	})

	t.Run("token config from env only", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir()) // no config file; everything via KMS_*
		t.Setenv("KMS_RESTAPI_ENDPOINT", expectedEndpoint)
		t.Setenv("KMS_KEY_ID", expectedKeyID)
		t.Setenv("KMS_RESTAPI_TYPE", "token") // token auth must be requested explicitly
		t.Setenv("KMS_RESTAPI_OKMSID", expectedID)
		t.Setenv("KMS_RESTAPI_TOKEN", expectedToken)

		cfg, err := NewConfig(nil)
		require.NoError(t, err)

		assert.Equal(t, expectedEndpoint, cfg.Endpoint)
		assert.Equal(t, expectedKeyID, cfg.KeyID)
		assert.Equal(t, expectedID, cfg.Auth.OkmsID)
		assert.Equal(t, expectedToken, cfg.Auth.Token)
		assert.Equal(t, int32(256), cfg.KeyBits) // default applied
	})

	t.Run("auth type defaults to mtls when unset", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		t.Setenv("KMS_RESTAPI_ENDPOINT", expectedEndpoint)
		t.Setenv("KMS_KEY_ID", expectedKeyID)
		// A token alone no longer selects token auth: the default is mtls, which then
		// requires a client certificate and key.
		t.Setenv("KMS_RESTAPI_TOKEN", expectedToken)

		_, err := NewConfig(nil)
		assert.ErrorContains(t, err, "client certificate")
	})

	t.Run("valid token config", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("HOME", copyTestConfig(t, "valid_token_config.yaml"))
		tc, err := testutils.GenerateTestCert("ecdsa")
		require.NoError(t, err)

		caPath := testutils.WriteDataToTempFile(t, dir, "ca.pem", tc.CertPEM)

		t.Setenv("KMS_RESTAPI_ENDPOINT", expectedEndpoint)
		t.Setenv("KMS_RESTAPI_CA", caPath)

		cfg, err := NewConfig([]string{"--key-id", expectedKeyID, "--key-name", "my-tofu-data-key"})
		require.NoError(t, err)

		assert.Equal(t, expectedID, cfg.Auth.OkmsID)
		assert.Equal(t, expectedToken, cfg.Auth.Token)
		assert.Equal(t, "token", cfg.Auth.Type)
		assert.Equal(t, expectedEndpoint, cfg.Endpoint)
		assert.Equal(t, expectedKeyID, cfg.KeyID)
		assert.Equal(t, int32(256), cfg.KeyBits)
		assert.Equal(t, "my-tofu-data-key", cfg.KeyName)
		assert.Equal(t, caPath, cfg.CA)
		assert.NotNil(t, cfg.TlsConfig)
	})

	t.Run("flags override environment for per-key settings", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		t.Setenv("KMS_RESTAPI_ENDPOINT", expectedEndpoint)
		t.Setenv("KMS_RESTAPI_TYPE", "token")
		t.Setenv("KMS_RESTAPI_OKMSID", expectedID)
		t.Setenv("KMS_RESTAPI_TOKEN", expectedToken)

		t.Setenv("KMS_KEY_ID", "00000000-0000-0000-0000-000000000000")
		t.Setenv("KMS_KEY_BITS", "128")

		const flagKeyID = "22222222-2222-2222-2222-222222222222"
		cfg, err := NewConfig([]string{
			"--key-id", flagKeyID,
			"--key-name", "flag-key",
			"--key-bits", "192",
		})
		require.NoError(t, err)

		assert.Equal(t, flagKeyID, cfg.KeyID, "flag must override env")
		assert.Equal(t, "flag-key", cfg.KeyName)
		assert.Equal(t, int32(192), cfg.KeyBits, "flag must override env")
	})
}
