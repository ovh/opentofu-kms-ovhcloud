# opentofu-kms-ovhcloud

[![build-and-test](https://github.com/ovh/opentofu-kms-ovhcloud/actions/workflows/build_and_test.yaml/badge.svg)](https://github.com/ovh/opentofu-kms-ovhcloud/actions/workflows/build_and_test.yaml)

[OpenTofu](https://opentofu.org) [external key provider](https://opentofu.org/docs/language/state/encryption/#external-experimental) for [OVHcloud KMS](https://docs.ovhcloud.com/en/guides/manage-and-operate/kms/quick-start).

It encrypts your OpenTofu **state and plan files** with a data key that is generated and wrapped by the OVHcloud Key Management Service.
The plaintext data key never leaves your machine in stored form: only its KMS-wrapped form is written alongside the encrypted state,
and it is unwrapped through the KMS again when OpenTofu needs to decrypt.

OpenTofu talks to this program through its [external key provider protocol](https://opentofu.org/docs/language/state/encryption/#writing-an-external-key-provider); you never run it directly.

## Table of Contents

- [Installation](#installation)
  - [Installation command](#installation-command)
  - [Binary download](#binary-download)
  - [Install from the source](#install-from-source)
- [Configuration](#configuration)
  - [Authentication](#authentication)
    - [mTLS](#mtls)
    - [Token](#token)
  - [Choosing the key](#choosing-the-key)
  - [Reference](#reference)
- [Usage](#usage)
- [Related links](#related-links)

## Installation

The binary must be on your `PATH` so OpenTofu can launch it.

### Installation command

```sh
curl -fsSL https://raw.githubusercontent.com/ovh/opentofu-kms-ovhcloud/main/install.sh | sh
```

The binary is installed in `$HOME/.local/bin` by default (created if it does not exist).
Make sure this directory is in your `PATH`.

**Install a specific version**:

```sh
curl -fsSL https://raw.githubusercontent.com/ovh/opentofu-kms-ovhcloud/main/install.sh | sh -s <version>
```

**Custom installation directory**:

```sh
curl -fsSL https://raw.githubusercontent.com/ovh/opentofu-kms-ovhcloud/main/install.sh | sh -s -- -b <path>
```

### Binary download

1. Download [latest release](https://github.com/ovh/opentofu-kms-ovhcloud/releases/latest)
2. Untar / unzip the archive
3. Add the containing folder to your `PATH` environment variable, or move the binary into a directory that is already in your `PATH`

### Install from source

Requires Go. Either install it directly:

```sh
go install github.com/ovh/opentofu-kms-ovhcloud/cmd/opentofu-kms-ovhcloud@latest
```

or build it locally:

```sh
git clone https://github.com/ovh/opentofu-kms-ovhcloud.git
cd opentofu-kms-ovhcloud
make install # installs to /usr/local/bin (override with PREFIX=...)
```

## Configuration

Configuration is split into two groups that live in two different places:

1. **Authentication & connection** - how to reach and authenticate to your KMS (`endpoint`, CA, credentials). It is read from a YAML file and/or `KMS_RESTAPI_*` environment variables.
2. **Key selection** - which key to use (`--key-id`, and optionally a name and size). This belongs with your project,
so it is passed as command-line flags inside your OpenTofu `key_provider` block (or with `KMS_KEY_*` environment variables as a fallback).

### Authentication

Authentication settings are read from the YAML file `~/.ovh-kms/okms.yaml` (or the path in the `KMS_CONFIG` environment variable).
Any value can be overridden with the matching `KMS_RESTAPI_*` environment variable.

The file is organized into **profiles**; the active profile defaults to `default` and is chosen by the top-level `profile` key.

There are two authentication methods:

#### mTLS

```yaml
version: 1
profile: default
profiles:
  default:
    restapi:
      endpoint: https://eu-west-rbx.okms.ovh.net
      ca: /path/to/public-ca.crt # optional if the CA is in the system trust store
      auth:
        cert: /path/to/domain/cert.pem
        key: /path/to/domain/key.pem
```

#### Token

```yaml
version: 1
profile: default
profiles:
  default:
    restapi:
      endpoint: https://eu-west-rbx.okms.ovh.net
      ca: /path/to/public-ca.crt # optional if the CA is in the system trust store
      auth:
        type: token
        okmsId: 11111111-1111-1111-1111-111111111111
        token: my-token
```

> The authentication method is `mtls` by default. You can set `auth.type` explicitly to `mtls` or `token`.

### Choosing the key

The key is selected with command-line flags in the OpenTofu `command` block (see [Usage](#usage)):

| Flag         | Required | Default | Description                                              |
|--------------|----------|---------|----------------------------------------------------------|
| `--key-id`   | yes      | -       | UUID of the service key used to wrap/unwrap the data key |
| `--key-name` | no       | -       | Name attached to the generated data key                  |
| `--key-bits` | no       | `256`   | Data key size in bits: `128`, `192` or `256`             |

Each flag falls back to an environment variable (`KMS_KEY_ID`, `KMS_KEY_NAME`, `KMS_KEY_BITS`) when the flag is not given; the flag wins when both are set.

### Reference

**Authentication & connection** - YAML key under `profiles.<profile>.restapi`, or environment variable (the environment overrides the file):

| YAML key      | Environment variable   | Required               | Default            | Description                         |
|---------------|------------------------|------------------------|--------------------|-------------------------------------|
| `endpoint`    | `KMS_RESTAPI_ENDPOINT` | yes                    | -                  | KMS REST API endpoint URL           |
| `ca`          | `KMS_RESTAPI_CA`       | no                     | system trust store | Path to a custom CA certificate     |
| `auth.type`   | `KMS_RESTAPI_TYPE`     | no                     | `mtls`             | `mtls` or `token`                   |
| `auth.cert`   | `KMS_RESTAPI_CERT`     | if `auth.type = mtls`  | -                  | Path to the mTLS client certificate |
| `auth.key`    | `KMS_RESTAPI_KEY`      | if `auth.type = mtls`  | -                  | Path to the mTLS client private key |
| `auth.okmsId` | `KMS_RESTAPI_OKMSID`   | if `auth.type = token` | -                  | UUID of the KMS instance            |
| `auth.token`  | `KMS_RESTAPI_TOKEN`    | if `auth.type = token` | -                  | REST API token                      |

The config-file location itself is set with `KMS_CONFIG` (default `~/.ovh-kms/okms.yaml`).

**Key selection** - command-line flag, or environment variable (the flag overrides the environment):

| Flag         | Environment variable | Required | Default |
|--------------|----------------------|----------|---------|
| `--key-id`   | `KMS_KEY_ID`         | yes      | -       |
| `--key-name` | `KMS_KEY_NAME`       | no       | -       |
| `--key-bits` | `KMS_KEY_BITS`       | no       | `256`   |

## Usage

Add an `encryption` block to your OpenTofu configuration, pointing the external key provider at this binary:

```hcl
terraform {
  encryption {
    key_provider "external" "ovhcloud" {
      command = [
        "opentofu-kms-ovhcloud",
        "--key-id", "00000000-0000-0000-0000-000000000000",
        # "--key-name", "my-tofu-data-key", # optional
        # "--key-bits", "256", # optional
      ]
    }

    method "aes_gcm" "ovhcloud" {
      keys = key_provider.external.ovhcloud
    }

    state {
      method = method.aes_gcm.ovhcloud
    }
    plan {
      method = method.aes_gcm.ovhcloud
    }
  }
}
```

## Related links

* Contribute: https://github.com/ovh/opentofu-kms-ovhcloud/blob/main/CONTRIBUTING.md
* Report bugs: https://github.com/ovh/opentofu-kms-ovhcloud/issues
