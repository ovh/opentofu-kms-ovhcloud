// SPDX-FileCopyrightText: 2026 OVH SAS <opensource@ovh.net>
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ovh/opentofu-kms-ovhcloud/pkg/utils"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

type Config struct {
	Endpoint  string `koanf:"endpoint"`
	CA        string `koanf:"ca"`
	KeyID     string
	KeyBits   int32
	KeyName   string
	Auth      AuthConfig `koanf:"auth"`
	TlsConfig *tls.Config
}

type AuthConfig struct {
	Type   string `koanf:"type"`
	Cert   string `koanf:"cert"`
	Key    string `koanf:"key"`
	OkmsID string `koanf:"okmsId"`
	Token  string `koanf:"token"`
}

const (
	envPrefix        = "KMS_"
	restapiEnvPrefix = envPrefix + "RESTAPI_"
	keyEnvPrefix     = envPrefix + "KEY_"

	defaultProfile    = "default"
	defaultConfigDir  = ".ovh-kms"
	defaultConfigFile = "okms.yaml"
	defaultKeyBits    = 256
)

// NewConfig loads the application configuration.
//
// Authentication and connection settings are read from a configuration file (the one set by
// the user or the default one) and may be overridden by environment variables. The per-key
// operational settings (key id, name and size) are read from the given command-line args,
// falling back to environment variables.
//
// Finally, the configuration is validated to ensure it is correct.
//
// Returns:
//   - *Config: the configuration instance.
//   - error: if any step fails. In case of validation errors, they will be grouped into a single error.
func NewConfig(args []string) (*Config, error) {
	k := koanf.New(".")

	if err := loadConfigFile(k); err != nil {
		return nil, err
	}
	profile := resolveProfile(k)
	if err := loadEnvConfig(k, profile); err != nil {
		return nil, err
	}
	cfg, err := unmarshalConfig(k, profile)
	if err != nil {
		return nil, err
	}

	if err := resolveKeyParams(cfg, args); err != nil {
		return nil, err
	}

	applyDefaults(cfg)
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	tlsConfig, err := buildTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	cfg.TlsConfig = tlsConfig
	return cfg, nil
}

// resolveKeyParams fills the per-key settings (key id, name and size) from command-line
// flags, defaulting each flag to environment variable so flags override
// the environment. These are not read from the configuration file.
func resolveKeyParams(cfg *Config, args []string) error {
	fs := flag.NewFlagSet("opentofu-kms-ovhcloud", flag.ContinueOnError)

	keyID := fs.String("key-id", os.Getenv(keyEnvPrefix+"ID"),
		"UUID of the service key used to wrap/unwrap the data key")
	keyName := fs.String("key-name", os.Getenv(keyEnvPrefix+"NAME"),
		"name attached to the generated data key")
	keyBits := fs.String("key-bits", os.Getenv(keyEnvPrefix+"BITS"),
		"data key size in bits: 128, 192 or 256 (default 256)")

	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("parse arguments: %w", err)
	}

	cfg.KeyID = *keyID
	cfg.KeyName = *keyName
	if *keyBits != "" {
		bits, err := strconv.ParseInt(*keyBits, 10, 32)
		if err != nil {
			return fmt.Errorf("key_bits must be an integer, got %q: %w", *keyBits, err)
		}
		cfg.KeyBits = int32(bits)
	}

	return nil
}

// buildTLSConfig assembles the *tls.Config from the validated configuration: the root CA
// pool and, for mTLS, the client certificate. For mTLS it also derives the okms id from the
// client certificate and validates it.
func buildTLSConfig(cfg *Config) (*tls.Config, error) {
	pool, err := utils.LoadCertPool(cfg.CA)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    pool,
	}

	if resolveAuthType(cfg) == "mtls" {
		certs, err := utils.LoadX509KeyPair(cfg.Auth.Cert, cfg.Auth.Key)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = certs

		okmsID, err := utils.GetOkmsIDFromCert(certs[0].Leaf)
		if err != nil {
			return nil, err
		}
		if err := validateOkmsID(okmsID); err != nil {
			return nil, err
		}
		cfg.Auth.OkmsID = okmsID
	}

	return tlsConfig, nil
}

// loadConfigFile loads the config file from KMS_CONFIG path or the default one.
func loadConfigFile(k *koanf.Koanf) error {
	cfgPath := os.Getenv(envPrefix + "CONFIG")
	if cfgPath == "" {
		homePath, err := os.UserHomeDir()
		if err != nil {
			return nil // non-fatal (variables can be set in the environment)
		}
		cfgPath = filepath.Join(homePath, defaultConfigDir, defaultConfigFile)
	}

	// #nosec G703 -- config path intentionally user-controlled
	if _, err := os.Stat(cfgPath); errors.Is(err, os.ErrNotExist) {
		return nil // non-fatal (variables can be set in the environment)
	}
	if err := k.Load(file.Provider(cfgPath), yaml.Parser()); err != nil {
		return fmt.Errorf("load config file: %w", err)
	}
	return nil
}

func resolveProfile(k *koanf.Koanf) string {
	profile := k.String("profile")
	if profile != "" {
		return profile
	}
	return defaultProfile
}

func unmarshalConfig(k *koanf.Koanf, profile string) (*Config, error) {
	var cfg Config

	path := strings.Join([]string{"profiles", profile, "restapi"}, ".")
	if err := k.Unmarshal(path, &cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}
	return &cfg, nil
}
