// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 HyvMind.io

package proxy_test

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/hyvmind-io/stellaris-auth-golang/internal/ca"
	"github.com/hyvmind-io/stellaris-auth-golang/internal/proxy"
)

func TestBypass_Match(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		host     string
		want     bool
	}{
		{"exact host with port", []string{"r2.example.com"}, "r2.example.com:443", true},
		{"exact bare host", []string{"r2.example.com"}, "r2.example.com", true},
		{"exact does not match subdomain", []string{"example.com"}, "a.example.com:443", false},
		{"case insensitive", []string{"Registry.Example.COM"}, "registry.example.com:443", true},
		{"leading dot matches subdomain", []string{".example.com"}, "a.b.example.com:443", true},
		{"leading dot excludes apex", []string{".example.com"}, "example.com:443", false},
		{"leading dot excludes lookalike", []string{".example.com"}, "badexample.com:443", false},
		{"host:port matches same port", []string{"reg.local:8443"}, "reg.local:8443", true},
		{"host:port rejects other port", []string{"reg.local:8443"}, "reg.local:443", false},
		{"wildcard", []string{"*"}, "anything:443", true},
		{"comma-separated entry", []string{"a.com, b.com"}, "b.com:443", true},
		{"trailing dot hostname", []string{"a.com"}, "a.com.:443", true},
		{"empty list", nil, "a.com:443", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := proxy.NewBypass(tc.patterns).Match(tc.host); got != tc.want {
				t.Errorf("Match(%q) with %v = %v; want %v", tc.host, tc.patterns, got, tc.want)
			}
		})
	}
}

func TestSplitHostList(t *testing.T) {
	got := proxy.SplitHostList([]string{"A.com, b.com,,", "a.com", " .c.org "})
	want := []string{"a.com", "b.com", ".c.org"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("SplitHostList = %v; want %v", got, want)
	}
}

// A bypassed host with a credential must be tunneled: the client sees the
// upstream's own certificate and no Bearer is injected.
func TestProxy_BypassWithCredentialTunnels(t *testing.T) {
	var (
		mu      sync.Mutex
		gotAuth string
	)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAuth = r.Header.Get("Authorization")
		mu.Unlock()
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)

	srv, _ := newTestProxyWithBypass(t, map[string]string{u.Hostname(): "secret"}, []string{u.Hostname()})

	upstreamPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw})
	client := proxyClient(t, srv.Addr(), upstreamPEM, false)

	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatalf("tunneled request verifying upstream cert: %v", err)
	}
	resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()
	if gotAuth != "" {
		t.Errorf("Authorization = %q; want none on bypassed host", gotAuth)
	}
}

// A child trusting only the bundle verifies a tunneled server signed by the
// parent SSL_CERT_FILE and a MITM'd registry signed by the proxy CA.
func TestProxy_BundleTrustsTunnelAndMITM(t *testing.T) {
	var (
		mu      sync.Mutex
		gotAuth string
	)
	registry := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAuth = r.Header.Get("Authorization")
		mu.Unlock()
	}))
	defer registry.Close()
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer backend.Close()

	srv, testCA := newTestProxy(t, map[string]string{"localhost": "tok"})

	dir := t.TempDir()
	parent := filepath.Join(dir, "corp.pem")
	backendPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: backend.Certificate().Raw})
	if err := os.WriteFile(parent, backendPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	bundle, err := ca.WriteBundle(dir, testCA.CertPEM, parent)
	if err != nil {
		t.Fatal(err)
	}
	bundlePEM, err := os.ReadFile(bundle.Path)
	if err != nil {
		t.Fatal(err)
	}
	client := proxyClient(t, srv.Addr(), bundlePEM, false)

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("tunneled backend not trusted via bundle: %v", err)
	}
	resp.Body.Close()

	ru, _ := url.Parse(registry.URL)
	resp, err = client.Get("https://localhost:" + ru.Port() + "/")
	if err != nil {
		t.Fatalf("MITM registry not trusted via bundle: %v", err)
	}
	resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()
	if gotAuth != "Bearer tok" {
		t.Errorf("Authorization = %q; want %q", gotAuth, "Bearer tok")
	}
}
