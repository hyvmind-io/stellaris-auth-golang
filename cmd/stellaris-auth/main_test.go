// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 HyvMind.io

package main

import (
	"slices"
	"testing"

	"github.com/spf13/cobra"
)

// TestRootCmd_argForwarding locks in the wrapper contract: stellaris-auth's own
// flags are parsed only when they precede the wrapped binary name, and every
// argument after the binary — including flags that collide with ours, shorthand
// bundles, and nested -- separators — is forwarded to the child verbatim.
//
// This is what makes wrapping toolchains like terragrunt work, e.g.
//
//	stellaris-auth terragrunt run --no-color --all -- plan
func TestRootCmd_argForwarding(t *testing.T) {
	tests := []struct {
		name        string
		argv        []string
		wantForward []string // args handed to the child (binary + its args)
		wantVerbose bool     // whether our --verbose was consumed
	}{
		{
			name:        "terragrunt with colliding flags and nested separator",
			argv:        []string{"terragrunt", "run", "--no-color", "--all", "--", "plan"},
			wantForward: []string{"terragrunt", "run", "--no-color", "--all", "--", "plan"},
		},
		{
			name:        "our flag before binary is consumed, rest forwarded",
			argv:        []string{"--verbose", "tofu", "apply"},
			wantForward: []string{"tofu", "apply"},
			wantVerbose: true,
		},
		{
			name:        "child -v is forwarded, not swallowed as --verbose",
			argv:        []string{"tofu", "plan", "-v"},
			wantForward: []string{"tofu", "plan", "-v"},
		},
		{
			name:        "child shorthand bundle is forwarded intact",
			argv:        []string{"tofu", "-chdir=foo", "plan"},
			wantForward: []string{"tofu", "-chdir=foo", "plan"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset the globals the parser writes to, then capture the parsed
			// positional args instead of starting the proxy/child.
			verbose = false
			var gotForward []string
			origRunE := rootCmd.RunE
			rootCmd.RunE = func(_ *cobra.Command, args []string) error {
				gotForward = args
				return nil
			}
			t.Cleanup(func() { rootCmd.RunE = origRunE })

			rootCmd.SetArgs(tt.argv)
			if err := rootCmd.Execute(); err != nil {
				t.Fatalf("Execute(%v) error: %v", tt.argv, err)
			}

			if !slices.Equal(gotForward, tt.wantForward) {
				t.Errorf("forwarded args = %v, want %v", gotForward, tt.wantForward)
			}
			if verbose != tt.wantVerbose {
				t.Errorf("verbose = %v, want %v", verbose, tt.wantVerbose)
			}
		})
	}
}
