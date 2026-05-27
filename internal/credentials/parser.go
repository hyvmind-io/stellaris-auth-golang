// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 HyvMind.io

package credentials

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// ParseOptions configures credential parsing sources.
type ParseOptions struct {
	// TofurcPath overrides default ~/.tofurc path.
	// If empty, checks TOFU_CLI_CONFIG_FILE env var, then defaults to ~/.tofurc.
	TofurcPath string

	// TerraformrcPath overrides default ~/.terraformrc path.
	// If empty, checks TF_CLI_CONFIG_FILE env var, then defaults to ~/.terraformrc.
	TerraformrcPath string

	// Environ is the environment variable slice to parse.
	// If nil, os.Environ() is used.
	Environ []string

	// RegistryHosts contains manual "host=token" overrides from --registry-host flag.
	RegistryHosts []string
}

// Parse reads credentials from all configured sources and merges them with
// the following priority order (highest wins):
//
//	Priority 1 (highest): --registry-host CLI overrides
//	Priority 2:           TF_TOKEN_* / TOFU_TOKEN_* environment variables
//	Priority 3:           ~/.tofurc credentials blocks
//	Priority 4 (lowest):  ~/.terraformrc credentials blocks
func Parse(opts ParseOptions) (*CredentialStore, error) {
	environ := opts.Environ
	if environ == nil {
		environ = os.Environ()
	}

	tofurcPath, terraformrcPath := resolveConfigPaths(opts, environ)

	store := New()

	// Priority 4 (lowest): ~/.terraformrc
	if terraformrcPath != "" {
		creds, err := parseHCLFile(terraformrcPath)
		if err != nil {
			return nil, fmt.Errorf("terraformrc: %w", err)
		}
		for host, token := range creds {
			slog.Debug("credentials: loaded from terraformrc", "hostname", host)
			store.Set(host, token)
		}
	}

	// Priority 3: ~/.tofurc
	if tofurcPath != "" {
		creds, err := parseHCLFile(tofurcPath)
		if err != nil {
			return nil, fmt.Errorf("tofurc: %w", err)
		}
		for host, token := range creds {
			slog.Debug("credentials: loaded from tofurc", "hostname", host)
			store.Set(host, token)
		}
	}

	// Priority 2: TF_TOKEN_* / TOFU_TOKEN_* environment variables
	envCreds := parseEnvVars(environ)
	for host, token := range envCreds {
		slog.Debug("credentials: loaded from environment", "hostname", host)
		store.Set(host, token)
	}

	// Priority 1 (highest): --registry-host CLI overrides
	flagCreds, err := parseRegistryHostFlags(opts.RegistryHosts)
	if err != nil {
		return nil, fmt.Errorf("registry-host flags: %w", err)
	}
	for host, token := range flagCreds {
		slog.Debug("credentials: loaded from CLI flag", "hostname", host)
		store.Set(host, token)
	}

	return store, nil
}

// resolveConfigPaths determines the tofurc and terraformrc paths to use.
// It checks the opts overrides first, then the environment variables, then
// falls back to the default home-directory paths.
func resolveConfigPaths(opts ParseOptions, environ []string) (tofurcPath, terraformrcPath string) {
	// Build a quick lookup map from the environ slice.
	envMap := make(map[string]string, len(environ))
	for _, e := range environ {
		k, v, ok := strings.Cut(e, "=")
		if ok {
			envMap[k] = v
		}
	}

	// Resolve tofurc path.
	tofurcPath = opts.TofurcPath
	if tofurcPath == "" {
		if v, ok := envMap["TOFU_CLI_CONFIG_FILE"]; ok {
			tofurcPath = v
		} else {
			home, err := os.UserHomeDir()
			if err == nil {
				tofurcPath = home + "/.tofurc"
			}
		}
	}

	// Resolve terraformrc path.
	terraformrcPath = opts.TerraformrcPath
	if terraformrcPath == "" {
		if v, ok := envMap["TF_CLI_CONFIG_FILE"]; ok {
			terraformrcPath = v
		} else {
			home, err := os.UserHomeDir()
			if err == nil {
				terraformrcPath = home + "/.terraformrc"
			}
		}
	}

	return tofurcPath, terraformrcPath
}

// parseHCLFile reads an HCL config file and extracts all credentials blocks.
// Files that do not exist are silently ignored (returns nil, nil).
// Other blocks (host {}, provider_installation {}, etc.) are safely skipped.
func parseHCLFile(path string) (map[string]string, error) {
	src, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	file, diags := hclsyntax.ParseConfig(src, path, hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return nil, fmt.Errorf("parsing %s: %s", path, diags.Error())
	}

	body := file.Body.(*hclsyntax.Body)
	creds := make(map[string]string)

	for _, block := range body.Blocks {
		if block.Type != "credentials" || len(block.Labels) == 0 {
			continue
		}
		hostname := strings.ToLower(block.Labels[0])
		tokenAttr, ok := block.Body.Attributes["token"]
		if !ok {
			continue
		}
		val, valDiags := tokenAttr.Expr.Value(nil)
		if valDiags.HasErrors() {
			continue
		}
		creds[hostname] = val.AsString()
	}

	return creds, nil
}

// parseEnvVars extracts credentials from TF_TOKEN_* and TOFU_TOKEN_* environment variables.
// The encoded hostname suffix is decoded via decodeHostname.
func parseEnvVars(environ []string) map[string]string {
	const (
		tfPrefix   = "TF_TOKEN_"
		tofuPrefix = "TOFU_TOKEN_"
	)

	creds := make(map[string]string)

	for _, e := range environ {
		k, v, ok := strings.Cut(e, "=")
		if !ok {
			continue
		}

		var encoded string
		switch {
		case strings.HasPrefix(k, tofuPrefix):
			encoded = strings.TrimPrefix(k, tofuPrefix)
		case strings.HasPrefix(k, tfPrefix):
			encoded = strings.TrimPrefix(k, tfPrefix)
		default:
			continue
		}

		hostname := decodeHostname(encoded)
		if hostname != "" {
			creds[hostname] = v
		}
	}

	return creds
}

// decodeHostname converts an encoded environment variable suffix into a hostname.
// Encoding rules (applied in order):
//
//	__  → - (hyphen)
//	_   → . (dot)
//
// For example:
//
//	registry_example_com       → registry.example.com
//	my__registry               → my-registry
//	my__registry_corp__internal_io → my-registry.corp-internal.io
func decodeHostname(encoded string) string {
	const placeholder = "\x00"
	s := strings.ReplaceAll(encoded, "__", placeholder) // __ → placeholder (FIRST!)
	s = strings.ReplaceAll(s, "_", ".")                 // _ → .
	s = strings.ReplaceAll(s, placeholder, "-")         // placeholder → -
	return s
}

// parseRegistryHostFlags parses "host=token" strings from the --registry-host CLI flag.
// Returns an error if any entry does not contain an "=" separator.
func parseRegistryHostFlags(flags []string) (map[string]string, error) {
	creds := make(map[string]string, len(flags))

	for _, flag := range flags {
		host, token, ok := strings.Cut(flag, "=")
		if !ok {
			return nil, fmt.Errorf("invalid --registry-host value %q: expected format host=token", flag)
		}
		creds[strings.ToLower(host)] = token
	}

	return creds, nil
}
