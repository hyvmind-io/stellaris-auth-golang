// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 HyvMind.io

package runner

import (
	"context"
	"io"
	"log/slog"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// silentLogger returns a *slog.Logger that discards all output — useful for
// tests that don't care about log output.
func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newTestRunner is a convenience helper that builds a Runner from cfg and
// calls t.Fatal if New returns an error.
func newTestRunner(t *testing.T, cfg Config) *Runner {
	t.Helper()
	r, err := New(cfg)
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}
	return r
}

// ---------------------------------------------------------------------------
// New
// ---------------------------------------------------------------------------

func TestNew_binaryNotFound(t *testing.T) {
	_, err := New(Config{
		Binary: "nonexistent-binary-xyz-123",
		Logger: silentLogger(),
	})
	if err == nil {
		t.Fatal("New() expected error for missing binary, got nil")
	}
}

func TestNew_binaryFound(t *testing.T) {
	r, err := New(Config{
		Binary: "echo",
		Logger: silentLogger(),
	})
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}
	if r == nil {
		t.Fatal("New() returned nil Runner")
	}
	if r.binPath == "" {
		t.Fatal("New() binPath is empty")
	}
}

// ---------------------------------------------------------------------------
// Run — exit code propagation
// ---------------------------------------------------------------------------

func TestRun_exitCode0(t *testing.T) {
	r := newTestRunner(t, Config{
		Binary: "echo",
		Args:   []string{"hello"},
		Logger: silentLogger(),
	})

	code, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}
	if code != 0 {
		t.Fatalf("Run() exit code = %d, want 0", code)
	}
}

func TestRun_exitCode1(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sh not available on Windows")
	}

	r := newTestRunner(t, Config{
		Binary: "sh",
		Args:   []string{"-c", "exit 1"},
		Logger: silentLogger(),
	})

	code, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}
	if code != 1 {
		t.Fatalf("Run() exit code = %d, want 1", code)
	}
}

func TestRun_exitCode42(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sh not available on Windows")
	}

	r := newTestRunner(t, Config{
		Binary: "sh",
		Args:   []string{"-c", "exit 42"},
		Logger: silentLogger(),
	})

	code, err := r.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}
	if code != 42 {
		t.Fatalf("Run() exit code = %d, want 42", code)
	}
}

// ---------------------------------------------------------------------------
// buildChildEnv
// ---------------------------------------------------------------------------

func TestBuildChildEnv_overrides(t *testing.T) {
	const proxyAddr = "http://127.0.0.1:8080"
	const caFile = "/tmp/ca.pem"

	env := buildChildEnv([]string{}, proxyAddr, caFile)

	wantPairs := map[string]string{
		"HTTPS_PROXY":         proxyAddr,
		"HTTP_PROXY":          proxyAddr,
		"SSL_CERT_FILE":       caFile,
		"NODE_EXTRA_CA_CERTS": caFile,
	}

	for key, wantVal := range wantPairs {
		found := false
		for _, entry := range env {
			if entry == key+"="+wantVal {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("buildChildEnv() missing or wrong entry for %s=%s; env = %v", key, wantVal, env)
		}
	}
}

func TestBuildChildEnv_noduplication(t *testing.T) {
	const proxyAddr = "http://127.0.0.1:8080"
	const caFile = "/tmp/ca.pem"

	parent := []string{
		"HTTPS_PROXY=http://old-proxy.example.com:3128",
		"PATH=/usr/bin:/bin",
	}

	env := buildChildEnv(parent, proxyAddr, caFile)

	// Count occurrences of HTTPS_PROXY entries.
	count := 0
	for _, entry := range env {
		if strings.HasPrefix(entry, "HTTPS_PROXY=") {
			count++
		}
	}
	if count != 1 {
		t.Errorf("buildChildEnv() HTTPS_PROXY appears %d times, want exactly 1; env = %v", count, env)
	}

	// The value must be the new one.
	newEntry := "HTTPS_PROXY=" + proxyAddr
	if !slices.Contains(env, newEntry) {
		t.Errorf("buildChildEnv() new HTTPS_PROXY value not found; env = %v", env)
	}
}

func TestBuildChildEnv_inherited(t *testing.T) {
	const proxyAddr = "http://127.0.0.1:8080"
	const caFile = "/tmp/ca.pem"

	parent := []string{
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"HOME=/home/user",
		"TERM=xterm-256color",
	}

	env := buildChildEnv(parent, proxyAddr, caFile)

	for _, entry := range parent {
		if !slices.Contains(env, entry) {
			t.Errorf("buildChildEnv() parent entry %q not preserved; env = %v", entry, env)
		}
	}
}

func TestBuildChildEnv_caseInsensitive(t *testing.T) {
	const proxyAddr = "http://127.0.0.1:8080"
	const caFile = "/tmp/ca.pem"

	// lowercase variant — must also be replaced.
	parent := []string{
		"https_proxy=http://old-proxy.example.com:3128",
		"PATH=/usr/bin",
	}

	env := buildChildEnv(parent, proxyAddr, caFile)

	// The old lowercase entry must be gone.
	for _, entry := range env {
		if strings.EqualFold(strings.SplitN(entry, "=", 2)[0], "https_proxy") &&
			strings.HasSuffix(entry, "old-proxy.example.com:3128") {
			t.Errorf("buildChildEnv() old lowercase https_proxy not removed; env = %v", env)
		}
	}

	// The canonical uppercase entry must be present with the new value.
	newEntry := "HTTPS_PROXY=" + proxyAddr
	if !slices.Contains(env, newEntry) {
		t.Errorf("buildChildEnv() new HTTPS_PROXY value not found; env = %v", env)
	}
}
