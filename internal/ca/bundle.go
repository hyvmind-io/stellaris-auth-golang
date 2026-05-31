// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 HyvMind.io

package ca

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// BundleFile is the filename of the child trust bundle written beside the CA.
const BundleFile = "stellaris-auth-bundle.pem"

// Bundle sources reported by WriteBundle.
const (
	BundleSourceParent = "parent SSL_CERT_FILE"
	BundleSourceSystem = "system roots"
	BundleSourceNone   = "none (proxy CA only)"
)

// systemRootFiles: well-known PEM root bundles; first readable one wins.
var systemRootFiles = []string{
	"/etc/ssl/certs/ca-certificates.crt",
	"/etc/pki/tls/certs/ca-bundle.crt",
	"/etc/ssl/ca-bundle.pem",
	"/etc/pki/tls/cacert.pem",
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
	"/etc/ssl/cert.pem",
}

// BundleResult describes the written trust bundle.
type BundleResult struct {
	Path   string
	Source string
	// Origin is the file the extra roots were read from ("" when none).
	Origin string
	// Certs is the number of CERTIFICATE blocks in the bundle.
	Certs int
}

// WriteBundle writes dir/BundleFile (0644) containing caCertPEM followed by
// the roots the child would otherwise trust: parentCertFile when non-empty,
// else the first readable system root file. Only CERTIFICATE blocks are copied.
func WriteBundle(dir string, caCertPEM []byte, parentCertFile string) (BundleResult, error) {
	return writeBundle(dir, caCertPEM, parentCertFile, systemRootFiles)
}

func writeBundle(dir string, caCertPEM []byte, parentCertFile string, systemFiles []string) (BundleResult, error) {
	res := BundleResult{Path: filepath.Join(dir, BundleFile), Source: BundleSourceNone}

	var buf bytes.Buffer
	n := appendCerts(&buf, caCertPEM)
	if n == 0 {
		return res, fmt.Errorf("ca: proxy CA PEM contains no certificate")
	}

	if parentCertFile != "" {
		data, err := os.ReadFile(parentCertFile)
		if err != nil {
			return res, fmt.Errorf("ca: read parent SSL_CERT_FILE %q: %w", parentCertFile, err)
		}
		res.Source, res.Origin = BundleSourceParent, parentCertFile
		n += appendCerts(&buf, data)
	} else {
		for _, f := range systemFiles {
			data, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			if c := appendCerts(&buf, data); c > 0 {
				res.Source, res.Origin = BundleSourceSystem, f
				n += c
				break
			}
		}
	}
	res.Certs = n

	if err := os.MkdirAll(dir, 0700); err != nil {
		return res, fmt.Errorf("ca: create directory %q: %w", dir, err)
	}
	if err := writePublicFile(res.Path, buf.Bytes()); err != nil {
		return res, fmt.Errorf("ca: write bundle %q: %w", res.Path, err)
	}
	return res, nil
}

// writePublicFile writes data with mode 0644 regardless of umask or the mode
// of a file already at path.
func writePublicFile(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0644); err != nil { //nolint:gosec // public certificates only
		return err
	}
	return os.Chmod(path, 0644) //nolint:gosec // public certificates only
}

// appendCerts re-encodes every CERTIFICATE block of data into buf and returns
// how many were written; keys and other block types are dropped.
func appendCerts(buf *bytes.Buffer, data []byte) int {
	n := 0
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return n
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		_ = pem.Encode(buf, &pem.Block{Type: block.Type, Bytes: block.Bytes})
		n++
	}
}
