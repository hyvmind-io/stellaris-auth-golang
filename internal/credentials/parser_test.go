// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 HyvMind.io

package credentials

import (
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// decodeHostname tests
// ---------------------------------------------------------------------------

func TestDecodeHostname_dots(t *testing.T) {
	got := decodeHostname("registry_example_com")
	want := "registry.example.com"
	if got != want {
		t.Errorf("decodeHostname(%q) = %q, want %q", "registry_example_com", got, want)
	}
}

func TestDecodeHostname_hyphens(t *testing.T) {
	got := decodeHostname("my__registry")
	want := "my-registry"
	if got != want {
		t.Errorf("decodeHostname(%q) = %q, want %q", "my__registry", got, want)
	}
}

func TestDecodeHostname_mixed(t *testing.T) {
	got := decodeHostname("my__registry_corp__internal_io")
	want := "my-registry.corp-internal.io"
	if got != want {
		t.Errorf("decodeHostname(%q) = %q, want %q", "my__registry_corp__internal_io", got, want)
	}
}

// ---------------------------------------------------------------------------
// parseHCLFile tests
// ---------------------------------------------------------------------------

func writeTempHCL(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.hcl")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("writeTempHCL: %v", err)
	}
	return path
}

func TestParseHCLFile_single(t *testing.T) {
	path := writeTempHCL(t, `
credentials "registry.example.com" {
  token = "abc123"
}
`)
	got, err := parseHCLFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(got))
	}
	if got["registry.example.com"] != "abc123" {
		t.Errorf("token = %q, want %q", got["registry.example.com"], "abc123")
	}
}

func TestParseHCLFile_multiple(t *testing.T) {
	path := writeTempHCL(t, `
credentials "registry.example.com" {
  token = "token-one"
}

credentials "models.example.io" {
  token = "token-two"
}
`)
	got, err := parseHCLFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 credentials, got %d", len(got))
	}
	if got["registry.example.com"] != "token-one" {
		t.Errorf("registry.example.com token = %q, want %q", got["registry.example.com"], "token-one")
	}
	if got["models.example.io"] != "token-two" {
		t.Errorf("models.example.io token = %q, want %q", got["models.example.io"], "token-two")
	}
}

func TestParseHCLFile_notexist(t *testing.T) {
	got, err := parseHCLFile("/nonexistent/path/that/does/not/exist.hcl")
	if err != nil {
		t.Fatalf("expected nil error for missing file, got: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil map for missing file, got: %v", got)
	}
}

func TestParseHCLFile_otherBlocks(t *testing.T) {
	// Real .tofurc / .terraformrc files can contain host {}, provider_installation {}, etc.
	// Only credentials blocks should be extracted; other blocks must be skipped silently.
	path := writeTempHCL(t, `
host "registry.example.com" {
  services = "custom"
}

provider_installation {
  network_mirror {
    url = "https://mirror.example.com/providers/"
  }
  direct {
    exclude = ["example.com/*/*"]
  }
}

credentials "registry.example.com" {
  token = "secret-token"
}
`)
	got, err := parseHCLFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 credential, got %d: %v", len(got), got)
	}
	if got["registry.example.com"] != "secret-token" {
		t.Errorf("token = %q, want %q", got["registry.example.com"], "secret-token")
	}
}

func TestParseHCLFile_malformed(t *testing.T) {
	path := writeTempHCL(t, `
credentials "registry.example.com" {
  token = INVALID HCL SYNTAX !!!
`)
	_, err := parseHCLFile(path)
	if err == nil {
		t.Fatal("expected error for malformed HCL, got nil")
	}
}

// ---------------------------------------------------------------------------
// parseEnvVars tests
// ---------------------------------------------------------------------------

func TestParseEnvVars_tftoken(t *testing.T) {
	environ := []string{
		"TF_TOKEN_registry_example_com=mytoken",
		"HOME=/home/user",
	}
	got := parseEnvVars(environ)
	if got["registry.example.com"] != "mytoken" {
		t.Errorf("registry.example.com token = %q, want %q", got["registry.example.com"], "mytoken")
	}
	if len(got) != 1 {
		t.Errorf("expected 1 credential, got %d: %v", len(got), got)
	}
}

func TestParseEnvVars_tofutoken(t *testing.T) {
	environ := []string{
		"TOFU_TOKEN_models_magnuschat_com=tofutoken456",
		"PATH=/usr/bin",
	}
	got := parseEnvVars(environ)
	if got["models.magnuschat.com"] != "tofutoken456" {
		t.Errorf("models.magnuschat.com token = %q, want %q", got["models.magnuschat.com"], "tofutoken456")
	}
	if len(got) != 1 {
		t.Errorf("expected 1 credential, got %d: %v", len(got), got)
	}
}

func TestParseEnvVars_noPrefix(t *testing.T) {
	environ := []string{
		"HOME=/home/user",
		"PATH=/usr/bin:/bin",
		"MY_SECRET=value",
		"TOKEN_something=other",
	}
	got := parseEnvVars(environ)
	if len(got) != 0 {
		t.Errorf("expected 0 credentials, got %d: %v", len(got), got)
	}
}

// ---------------------------------------------------------------------------
// parseRegistryHostFlags tests
// ---------------------------------------------------------------------------

func TestParseRegistryHostFlags_valid(t *testing.T) {
	flags := []string{
		"registry.example.com=token-abc",
		"models.io=token-xyz",
	}
	got, err := parseRegistryHostFlags(flags)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["registry.example.com"] != "token-abc" {
		t.Errorf("registry.example.com = %q, want %q", got["registry.example.com"], "token-abc")
	}
	if got["models.io"] != "token-xyz" {
		t.Errorf("models.io = %q, want %q", got["models.io"], "token-xyz")
	}
}

func TestParseRegistryHostFlags_invalid(t *testing.T) {
	flags := []string{"hostonly"}
	_, err := parseRegistryHostFlags(flags)
	if err == nil {
		t.Fatal("expected error for flag without '=', got nil")
	}
}

// ---------------------------------------------------------------------------
// Parse integration tests
// ---------------------------------------------------------------------------

func TestParse_priorityMerge(t *testing.T) {
	// Same hostname appears in all 4 sources. The highest-priority source must win.
	const hostname = "registry.example.com"

	terraformrcPath := writeTempHCL(t, `
credentials "registry.example.com" {
  token = "from-terraformrc"
}
`)
	tofurcPath := writeTempHCL(t, `
credentials "registry.example.com" {
  token = "from-tofurc"
}
`)

	environ := []string{
		"TF_TOKEN_registry_example_com=from-env",
	}

	registryHosts := []string{"registry.example.com=from-cli"}

	store, err := Parse(ParseOptions{
		TofurcPath:      tofurcPath,
		TerraformrcPath: terraformrcPath,
		Environ:         environ,
		RegistryHosts:   registryHosts,
	})
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	token, found := store.Lookup(hostname)
	if !found {
		t.Fatalf("hostname %q not found in store", hostname)
	}
	if token != "from-cli" {
		t.Errorf("token = %q, want %q (CLI should win)", token, "from-cli")
	}
}

func TestParse_differentHosts(t *testing.T) {
	// Each source contributes a unique hostname; all should be present after merge.
	terraformrcPath := writeTempHCL(t, `
credentials "tf-host.example.com" {
  token = "tf-token"
}
`)
	tofurcPath := writeTempHCL(t, `
credentials "tofu-host.example.com" {
  token = "tofu-token"
}
`)

	environ := []string{
		"TF_TOKEN_env__host_example_com=env-token",
	}

	registryHosts := []string{"cli-host.example.com=cli-token"}

	store, err := Parse(ParseOptions{
		TofurcPath:      tofurcPath,
		TerraformrcPath: terraformrcPath,
		Environ:         environ,
		RegistryHosts:   registryHosts,
	})
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	tests := []struct {
		host  string
		token string
	}{
		{"tf-host.example.com", "tf-token"},
		{"tofu-host.example.com", "tofu-token"},
		{"env-host.example.com", "env-token"},
		{"cli-host.example.com", "cli-token"},
	}

	for _, tt := range tests {
		tok, found := store.Lookup(tt.host)
		if !found {
			t.Errorf("host %q not found", tt.host)
			continue
		}
		if tok != tt.token {
			t.Errorf("host %q token = %q, want %q", tt.host, tok, tt.token)
		}
	}

	if store.Len() != 4 {
		t.Errorf("store.Len() = %d, want 4", store.Len())
	}
}

func TestParse_tofuCliConfigFile(t *testing.T) {
	// TOFU_CLI_CONFIG_FILE env var should override the default ~/.tofurc path.
	customTofurc := writeTempHCL(t, `
credentials "custom-tofu.example.com" {
  token = "custom-tofu-token"
}
`)

	environ := []string{
		"TOFU_CLI_CONFIG_FILE=" + customTofurc,
	}

	store, err := Parse(ParseOptions{
		// TofurcPath is intentionally empty — should be resolved from env.
		TerraformrcPath: "/nonexistent/path/.terraformrc",
		Environ:         environ,
	})
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	token, found := store.Lookup("custom-tofu.example.com")
	if !found {
		t.Fatal("expected credential from TOFU_CLI_CONFIG_FILE not found")
	}
	if token != "custom-tofu-token" {
		t.Errorf("token = %q, want %q", token, "custom-tofu-token")
	}
}

func TestParse_tfCliConfigFile(t *testing.T) {
	// TF_CLI_CONFIG_FILE env var should override the default ~/.terraformrc path.
	customTerraformrc := writeTempHCL(t, `
credentials "custom-tf.example.com" {
  token = "custom-tf-token"
}
`)

	environ := []string{
		"TF_CLI_CONFIG_FILE=" + customTerraformrc,
	}

	store, err := Parse(ParseOptions{
		TofurcPath: "/nonexistent/path/.tofurc",
		// TerraformrcPath is intentionally empty — should be resolved from env.
		Environ: environ,
	})
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	token, found := store.Lookup("custom-tf.example.com")
	if !found {
		t.Fatal("expected credential from TF_CLI_CONFIG_FILE not found")
	}
	if token != "custom-tf-token" {
		t.Errorf("token = %q, want %q", token, "custom-tf-token")
	}
}

// ---------------------------------------------------------------------------
// CredentialStore tests
// ---------------------------------------------------------------------------

func TestCredentialStore_caseInsensitive(t *testing.T) {
	store := New()
	store.Set("Registry.Example.COM", "mytoken")

	tests := []string{
		"registry.example.com",
		"REGISTRY.EXAMPLE.COM",
		"Registry.Example.Com",
		"REGISTRY.example.COM",
	}

	for _, h := range tests {
		token, found := store.Lookup(h)
		if !found {
			t.Errorf("Lookup(%q): not found", h)
			continue
		}
		if token != "mytoken" {
			t.Errorf("Lookup(%q) = %q, want %q", h, token, "mytoken")
		}
	}
}

// TestCredentialStore_LookupHostPort verifies that CredentialStore.Lookup
// performs exact matching: a credential stored with "host:port" is found by
// the same "host:port" key, NOT by the bare "host" alone.
//
// The bare-hostname fallback is intentionally handled by server.go:ServeHTTP,
// not by CredentialStore itself — this test documents and guards that contract.
func TestCredentialStore_LookupHostPort(t *testing.T) {
	store := New()
	store.Set("registry.example.com:3000", "port-token")

	t.Run("exact host:port match", func(t *testing.T) {
		tok, found := store.Lookup("registry.example.com:3000")
		if !found {
			t.Fatal("expected credential for exact host:port key, not found")
		}
		if tok != "port-token" {
			t.Errorf("token = %q, want %q", tok, "port-token")
		}
	})

	t.Run("bare hostname does NOT match host:port credential", func(t *testing.T) {
		// CredentialStore is exact-match only. The fallback that strips the port
		// lives in server.go:ServeHTTP, not here. Verify the contract is upheld.
		_, found := store.Lookup("registry.example.com")
		if found {
			t.Error("Lookup(bare hostname) should NOT match a credential stored with host:port; " +
				"the fallback belongs in server.go")
		}
	})

	t.Run("case insensitive host:port match", func(t *testing.T) {
		tok, found := store.Lookup("Registry.Example.COM:3000")
		if !found {
			t.Fatal("expected case-insensitive match for host:port, not found")
		}
		if tok != "port-token" {
			t.Errorf("token = %q, want %q", tok, "port-token")
		}
	})
}

// TestCredentialStore_LookupBareHostname verifies a credential stored with a
// bare hostname (no port) is found by the bare hostname, and NOT accidentally
// found by "hostname:someport" (which would require the fallback in server.go).
func TestCredentialStore_LookupBareHostname(t *testing.T) {
	store := New()
	store.Set("registry.example.com", "bare-token")

	t.Run("bare hostname match", func(t *testing.T) {
		tok, found := store.Lookup("registry.example.com")
		if !found {
			t.Fatal("expected credential for bare hostname, not found")
		}
		if tok != "bare-token" {
			t.Errorf("token = %q, want %q", tok, "bare-token")
		}
	})

	t.Run("host:port does NOT match bare hostname credential", func(t *testing.T) {
		// A lookup for "registry.example.com:443" must not match the bare-hostname
		// credential. The two-step fallback in server.go handles this case.
		_, found := store.Lookup("registry.example.com:443")
		if found {
			t.Error("Lookup(host:port) should NOT match a credential stored with bare hostname; " +
				"those are distinct keys in CredentialStore")
		}
	})
}
