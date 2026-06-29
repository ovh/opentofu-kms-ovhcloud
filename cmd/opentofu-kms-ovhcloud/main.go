// SPDX-FileCopyrightText: 2026 OVH SAS <opensource@ovh.net>
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"os"

	"github.com/ovh/opentofu-kms-ovhcloud/pkg/config"
	"github.com/ovh/opentofu-kms-ovhcloud/pkg/keyprovider"
)

func main() {
	// stdout is reserved for the protocol; all diagnostics go to stderr.
	log.SetOutput(os.Stderr)

	if err := writeHeader(os.Stdout); err != nil {
		log.Fatalf("failed to write header: %v", err)
	}

	// read the input. "null" means encryption only; otherwise it carries
	// the metadata stored alongside the encrypted data on a previous run.
	rawInput, err := io.ReadAll(os.Stdin)
	if err != nil {
		log.Fatalf("failed to read stdin: %v", err)
	}

	var input keyprovider.Input
	if err := json.Unmarshal(rawInput, &input); err != nil {
		log.Fatalf("failed to parse input: %v", err)
	}

	cfg, err := config.NewConfig(os.Args[1:])
	if err != nil {
		log.Fatalf("failed to load configuration: %v", err)
	}

	kp, err := keyprovider.New(cfg)
	if err != nil {
		log.Fatalf("failed to initialize key provider: %v", err)
	}

	// produce the key material and metadata.
	output, err := kp.Provide(context.Background(), input)
	if err != nil {
		log.Fatalf("failed to provide key: %v", err)
	}

	if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
		log.Fatalf("failed to write output: %v", err)
	}
}

// writeHeader writes the single-line protocol header followed by a newline.
func writeHeader(w io.Writer) error {
	header := keyprovider.Header{
		Magic:   keyprovider.HeaderMagic,
		Version: keyprovider.ProtocolVersion,
	}
	marshalledHeader, err := json.Marshal(header)
	if err != nil {
		return err
	}
	_, err = w.Write(append(marshalledHeader, '\n'))
	return err
}
