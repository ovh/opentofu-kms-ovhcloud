#!/bin/bash

set -uo pipefail

echo "E2E Tests"

BIN="${BIN:-./opentofu-kms-ovhcloud}"

fail() {
    echo "TEST FAILED: $1"
    exit 1
}

echo "[1/2] Encryption-only run..."
# The binary writes the protocol header on the first line, then the JSON output. Drop the header with "tail -n +2" before parsing.
out1=$(printf 'null' | "$BIN" | tail -n +2) \
    || fail "encryption run failed"

enc1=$(echo "$out1" | jq -r '.keys.encryption_key')
meta1=$(echo "$out1" | jq -c '.meta')
if [ -z "$enc1" ] || [ "$enc1" = "null" ]; then
    fail "no encryption key returned"
fi

echo "[2/2] Decryption round-trip..."
out2=$(printf '%s' "$meta1" | "$BIN" | tail -n +2) \
    || fail "decryption run failed"

dec2=$(echo "$out2" | jq -r '.keys.decryption_key')
[ "$enc1" == "$dec2" ] || fail "decryption key does not match the original encryption key"

echo "All E2E tests have succeeded"
