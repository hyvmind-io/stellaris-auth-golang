// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 HyvMind.io

package ca

import (
	"bytes"
	"encoding/pem"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func pemBlocks(t *testing.T, data []byte) []*pem.Block {
	t.Helper()
	var out []*pem.Block
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			return out
		}
		out = append(out, b)
	}
}

func testCAPEM(t *testing.T, dir string) *CA {
	t.Helper()
	c, err := NewManager(dir, slog.Default()).GenerateCA(false)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestWriteBundle(t *testing.T) {
	dir := t.TempDir()
	proxyCA := testCAPEM(t, filepath.Join(dir, "proxy"))
	other := testCAPEM(t, filepath.Join(dir, "other"))

	// Root file deliberately carries a private key that must be dropped.
	roots := filepath.Join(dir, "roots.pem")
	if err := os.WriteFile(roots, append(append([]byte{}, other.CertPEM...), other.KeyPEM...), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing.pem")

	tests := []struct {
		name       string
		parent     string
		system     []string
		wantSource string
		wantOrigin string
		wantCerts  int
	}{
		{"parent SSL_CERT_FILE", roots, []string{missing}, BundleSourceParent, roots, 2},
		{"system roots, first readable wins", "", []string{missing, roots}, BundleSourceSystem, roots, 2},
		{"no roots available", "", []string{missing}, BundleSourceNone, "", 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := t.TempDir()
			res, err := writeBundle(out, proxyCA.CertPEM, tc.parent, tc.system)
			if err != nil {
				t.Fatal(err)
			}
			if res.Source != tc.wantSource || res.Origin != tc.wantOrigin || res.Certs != tc.wantCerts {
				t.Errorf("result = %+v; want source=%q origin=%q certs=%d", res, tc.wantSource, tc.wantOrigin, tc.wantCerts)
			}
			data, err := os.ReadFile(res.Path)
			if err != nil {
				t.Fatal(err)
			}
			blocks := pemBlocks(t, data)
			if len(blocks) != tc.wantCerts {
				t.Fatalf("bundle has %d blocks; want %d", len(blocks), tc.wantCerts)
			}
			for _, b := range blocks {
				if b.Type != "CERTIFICATE" {
					t.Errorf("bundle contains %q block", b.Type)
				}
			}
			if !bytes.Equal(pem.EncodeToMemory(blocks[0]), proxyCA.CertPEM) {
				t.Error("first bundle entry is not the proxy CA")
			}
			if runtime.GOOS != "windows" {
				fi, _ := os.Stat(res.Path)
				if fi.Mode().Perm() != 0o644 {
					t.Errorf("bundle mode = %v; want 0644", fi.Mode().Perm())
				}
			}
		})
	}
}

func TestWriteBundle_regeneratesAndFixesMode(t *testing.T) {
	dir := t.TempDir()
	proxyCA := testCAPEM(t, filepath.Join(dir, "proxy"))
	path := filepath.Join(dir, BundleFile)
	if err := os.WriteFile(path, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := writeBundle(dir, proxyCA.CertPEM, "", nil); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if !bytes.Equal(data, proxyCA.CertPEM) {
		t.Errorf("bundle not regenerated: %q", data)
	}
	if fi, _ := os.Stat(path); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o644 {
		t.Errorf("mode = %v; want 0644", fi.Mode().Perm())
	}
}

func TestWriteBundle_parentMissingFails(t *testing.T) {
	dir := t.TempDir()
	proxyCA := testCAPEM(t, filepath.Join(dir, "proxy"))
	if _, err := WriteBundle(dir, proxyCA.CertPEM, filepath.Join(dir, "nope.pem")); err == nil {
		t.Error("want error for unreadable parent SSL_CERT_FILE")
	}
}
