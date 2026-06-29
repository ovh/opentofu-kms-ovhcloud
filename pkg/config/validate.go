// SPDX-FileCopyrightText: 2026 OVH SAS <opensource@ovh.net>
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
)

type validator func(*Config) error

// applyDefaults fills in default values for optional fields left unset. It must run
// before validation so defaulted values are validated like any other.
func applyDefaults(cfg *Config) {
	if cfg.KeyBits == 0 {
		cfg.KeyBits = defaultKeyBits
	}
}

// validateConfig validates the application configuration. It performs no mutation and
// builds no runtime objects; deriving the TLS configuration is the job of buildTLSConfig.
//
// For mTLS the okms id is extracted from the client certificate and is therefore validated
// in buildTLSConfig, where the certificate is loaded.
//
// Returns:
//   - error: any configuration errors. If there are multiple errors, they are grouped into a single error.
func validateConfig(cfg *Config) error {
	var errs []error
	validators := []validator{
		validateProtocol,
		validateKeyID,
		validateKeyBits,
		validateAuth,
	}

	for _, v := range validators {
		if err := v(cfg); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func validateProtocol(cfg *Config) error {
	if cfg.Endpoint == "" {
		return errors.New("missing endpoint")
	}
	return nil
}

func validateKeyID(cfg *Config) error {
	if cfg.KeyID == "" {
		return errors.New("missing key_id")
	}
	if _, err := uuid.Parse(cfg.KeyID); err != nil {
		return fmt.Errorf("key_id must be a valid UUID: %w", err)
	}
	return nil
}

func validateKeyBits(cfg *Config) error {
	switch cfg.KeyBits {
	case 128, 192, 256:
		return nil
	default:
		return fmt.Errorf("key_bits must be 128, 192 or 256, got %d", cfg.KeyBits)
	}
}

func validateAuth(cfg *Config) error {
	switch resolveAuthType(cfg) {
	case "mtls":
		return validateAuthMtls(cfg)
	case "token":
		return validateAuthToken(cfg)
	default:
		return fmt.Errorf("auth type not supported: %s", cfg.Auth.Type)
	}
}

// resolveAuthType returns the effective authentication mode. It defaults to mTLS.
func resolveAuthType(cfg *Config) string {
	if cfg.Auth.Type != "" {
		return cfg.Auth.Type
	}
	return "mtls"
}

func validateAuthMtls(cfg *Config) error {
	var errs []error
	if cfg.Auth.Cert == "" {
		errs = append(errs, errors.New("missing client certificate"))
	}
	if cfg.Auth.Key == "" {
		errs = append(errs, errors.New("missing client key"))
	}
	return errors.Join(errs...)
}

func validateAuthToken(cfg *Config) error {
	var errs []error

	if err := validateOkmsID(cfg.Auth.OkmsID); err != nil {
		errs = append(errs, err)
	}
	if cfg.Auth.Token == "" {
		errs = append(errs, errors.New("missing token"))
	}

	return errors.Join(errs...)
}

func validateOkmsID(id string) error {
	if id == "" {
		return errors.New("missing okms id")
	}
	if _, err := uuid.Parse(id); err != nil {
		return fmt.Errorf("okms id must be a valid UUID: %w", err)
	}
	return nil
}
