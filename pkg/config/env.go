// SPDX-FileCopyrightText: 2026 OVH SAS <opensource@ovh.net>
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"

	"github.com/knadh/koanf/providers/env/v2"
	"github.com/knadh/koanf/v2"
)

// envSuffixToKey maps a KMS_RESTAPI_<SUFFIX> environment variable to its
// configuration key relative to "profiles.<profile>.restapi".
//
// These are the authentication and connection variables for the OVHcloud KMS key provider.
// The per-key settings (KMS_KEY_ID, KMS_KEY_NAME, KMS_KEY_BITS) are deliberately absent:
// they are resolved as command-line flags (see resolveKeyParams), which fall back to those
// environment variables. Any other KMS_* variable (e.g. KMS_CONFIG) is ignored.
var envSuffixToKey = map[string]string{
	"ENDPOINT": "endpoint",
	"CA":       "ca",
	"TYPE":     "auth.type",
	"CERT":     "auth.cert",
	"KEY":      "auth.key",
	"OKMSID":   "auth.okmsId",
	"TOKEN":    "auth.token",
}

// loadEnvConfig overrides config with KMS_RESTAPI_* environment variables.
func loadEnvConfig(k *koanf.Koanf, profile string) error {
	return k.Load(env.Provider(".", env.Opt{
		Prefix:        restapiEnvPrefix,
		TransformFunc: normalizeEnvVar(profile),
	}), nil)
}

// normalizeEnvVar maps a KMS_RESTAPI_* environment variable to the matching koanf
// key under the active profile. Unknown variables are dropped (empty key).
//
// Example: "KMS_RESTAPI_OKMSID" -> "profiles.default.restapi.auth.okmsId".
func normalizeEnvVar(profile string) func(string, string) (string, any) {
	return func(key, value string) (string, any) {
		suffix := strings.TrimPrefix(key, restapiEnvPrefix)
		rel, ok := envSuffixToKey[suffix]
		if !ok {
			return "", nil
		}
		return strings.Join([]string{"profiles", profile, "restapi", rel}, "."), value
	}
}
