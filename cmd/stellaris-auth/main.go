// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 HyvMind.io

// stellaris-auth is a transparent HTTPS forward proxy that injects Terraform /
// OpenTofu registry credentials into child processes without requiring any
// changes to the toolchain configuration.
//
// Usage:
//
//	stellaris-auth setup                        # Generate and trust CA certificate
//	stellaris-auth [flags] tofu [args...]       # Wrap OpenTofu command
//	stellaris-auth [flags] terraform [args...]  # Wrap Terraform command
//	stellaris-auth [flags] terragrunt [args...] # Wrap Terragrunt command
//
// stellaris-auth's own flags must precede the wrapped binary name; every
// argument after the binary is forwarded to it untouched.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/hyvmind-io/stellaris-auth/internal/ca"
	"github.com/hyvmind-io/stellaris-auth/internal/credentials"
	"github.com/hyvmind-io/stellaris-auth/internal/proxy"
	"github.com/hyvmind-io/stellaris-auth/internal/runner"
)

var version = "dev" // set via -ldflags "-X main.version=x.y.z" at build time

// Persistent flags (available to root command and all subcommands).
var (
	port          int
	verbose       bool
	insecure      bool
	caDir         string
	registryHosts []string
)

// Setup-specific flags.
var forceSetup bool

// rootCmd is the main entry point — it wraps tofu/terraform child processes.
var rootCmd = &cobra.Command{
	Use:   "stellaris-auth [flags] <binary> [args...]",
	Short: "Inject Terraform/OpenTofu registry credentials transparently",
	Long: `stellaris-auth starts a transparent HTTPS forward proxy that injects
bearer tokens for known registry hosts, then runs tofu or terraform with
HTTPS_PROXY and SSL_CERT_FILE pointed at the proxy and CA certificate.

Examples:
  stellaris-auth tofu init
  stellaris-auth terraform plan -out=tfplan
  stellaris-auth --port 9090 --verbose tofu apply
  stellaris-auth terragrunt run --no-color --all -- plan

stellaris-auth flags must come before the binary name; all arguments after
the binary (including flags that collide with stellaris-auth's own, such as
-v, and nested -- separators) are forwarded to the child verbatim.`,
	// Require at least the binary name (e.g. "tofu") as the first non-flag arg.
	Args: cobra.MinimumNArgs(1),
	// SetInterspersed(false) (configured in init) stops stellaris-auth flag
	// parsing at the first positional argument — the wrapped binary — so every
	// subsequent argument is passed through to the child untouched.
	RunE: runRootCmd,
}

// setupCmd generates (or regenerates) the CA certificate.
var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Generate the stellaris-auth CA certificate and print trust instructions",
	Long: `setup generates a new RSA 4096-bit self-signed CA certificate and writes
it to the CA directory (default: ~/.stellaris-auth/ca/).

If a certificate already exists, use --force to overwrite it.`,
	Args: cobra.NoArgs,
	RunE: runSetupCmd,
}

// versionCmd prints the version string.
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the stellaris-auth version",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("stellaris-auth version %s\n", version)
		return nil
	},
}

func init() {
	// Stop parsing stellaris-auth flags at the first positional argument (the
	// wrapped binary name). Everything after the binary — including flags that
	// collide with ours (-v, --verbose), shorthand bundles (-chdir=...), and
	// nested -- separators — is forwarded verbatim to the child process. This
	// lets us wrap arbitrary toolchains such as:
	//   stellaris-auth tg run --no-color --all -- plan
	//   stellaris-auth tofu plan -v
	// stellaris-auth's own flags must precede the binary name.
	rootCmd.Flags().SetInterspersed(false)

	// Persistent flags — available on root and all subcommands.
	rootCmd.PersistentFlags().IntVarP(&port, "port", "p", 0,
		"Proxy listen port on 127.0.0.1 (default: OS-assigned)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false,
		"Enable debug logging")
	rootCmd.PersistentFlags().BoolVar(&insecure, "insecure", false,
		"Disable upstream TLS certificate verification (use only for dev/self-signed certs)")
	rootCmd.PersistentFlags().StringVar(&caDir, "ca-dir", "",
		"CA certificate directory (default: ~/.stellaris-auth/ca/)")
	rootCmd.PersistentFlags().StringArrayVar(&registryHosts, "registry-host", nil,
		"host=token credential override (repeatable)")

	// Setup-specific flags.
	setupCmd.Flags().BoolVar(&forceSetup, "force", false,
		"Regenerate CA certificate even if one already exists")

	// Environment variable fallback resolution runs before every command.
	rootCmd.PersistentPreRunE = resolveEnvVarFlags

	rootCmd.AddCommand(setupCmd)
	rootCmd.AddCommand(versionCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// runRootCmd is the main proxy + child-process flow.
func runRootCmd(cmd *cobra.Command, args []string) error {
	logger := buildLogger(verbose)

	// Warn if HTTPS_PROXY is already set in the parent environment.
	if existing := os.Getenv("HTTPS_PROXY"); existing != "" {
		logger.Warn("HTTPS_PROXY is already set. stellaris-auth will override it for the child process.",
			slog.String("existing", existing))
	}

	// Resolve CA directory (expand ~ prefix).
	resolvedCADir, err := resolvePath(caDir)
	if err != nil {
		return fmt.Errorf("resolving --ca-dir: %w", err)
	}

	// Parse credentials from all sources.
	store, err := credentials.Parse(credentials.ParseOptions{
		RegistryHosts: registryHosts,
		Environ:       os.Environ(),
	})
	if err != nil {
		return fmt.Errorf("loading credentials: %w", err)
	}

	// FR-107: fail early if no credentials were found at all.
	if store.Len() == 0 {
		return fmt.Errorf(
			"no registry credentials found\n\n" +
				"stellaris-auth requires at least one credential to be configured.\n" +
				"Sources checked (highest priority first):\n" +
				"  1. --registry-host host=token flags\n" +
				"  2. TF_TOKEN_* / TOFU_TOKEN_* environment variables\n" +
				"  3. ~/.tofurc credentials blocks\n" +
				"  4. ~/.terraformrc credentials blocks\n",
		)
	}

	// FR-106: log discovered hosts (never tokens) when verbose.
	if verbose {
		for _, h := range store.Hostnames() {
			logger.Debug("discovered credential", slog.String("hostname", h))
		}
	}

	// Ensure CA exists (load existing or generate new).
	caManager := ca.NewManager(resolvedCADir, logger)
	caData, err := caManager.EnsureCA()
	if err != nil {
		return fmt.Errorf("ensuring CA: %w", err)
	}
	certPath := caManager.CertPath()

	// Build proxy listen address.
	listenAddr := fmt.Sprintf("127.0.0.1:%d", port) // port==0 → OS assigns
	if port == 0 {
		listenAddr = "127.0.0.1:0"
	}

	// Build optional upstream TLS override.
	var upstreamTLSConfig *tls.Config
	if insecure {
		logger.Warn("--insecure: upstream TLS certificate verification disabled")
		upstreamTLSConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}

	// Create the proxy server.
	srv := proxy.New(proxy.Config{
		Addr:              listenAddr,
		Credentials:       store,
		CA:                caData,
		CertCache:         ca.NewCache(),
		Logger:            logger,
		UpstreamTLSConfig: upstreamTLSConfig,
	})

	// Start proxy in a goroutine; it will block until Shutdown is called.
	proxyErrCh := make(chan error, 1)
	go func() {
		proxyErrCh <- srv.ListenAndServe()
	}()

	// Wait for the proxy to be ready (listener bound and Addr() non-empty).
	if err := waitForProxy(srv, 5*time.Second); err != nil {
		return fmt.Errorf("starting proxy: %w", err)
	}

	proxyAddr := "http://" + srv.Addr()
	if verbose {
		logger.Debug("proxy listening", slog.String("addr", proxyAddr))
	}

	// Create and run the child process.
	childRunner, err := runner.New(runner.Config{
		Binary:    args[0],
		Args:      args[1:],
		ProxyAddr: proxyAddr,
		CAFile:    certPath,
		Logger:    logger,
	})
	if err != nil {
		return fmt.Errorf("resolving binary: %w", err)
	}

	exitCode, runErr := childRunner.Run(cmd.Context())

	// Gracefully shut down the proxy regardless of child exit code.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Warn("proxy shutdown error", slog.String("error", err.Error()))
	}

	// Re-check if proxy itself failed for a reason other than graceful shutdown.
	select {
	case pErr := <-proxyErrCh:
		if pErr != nil {
			logger.Warn("proxy exited with error", slog.String("error", pErr.Error()))
		}
	default:
	}

	if runErr != nil {
		return fmt.Errorf("running %s: %w", args[0], runErr)
	}

	// Propagate the child's exit code directly — do NOT return a cobra error
	// (that would be converted to exit code 1 regardless).
	if exitCode != 0 {
		os.Exit(exitCode)
	}
	return nil
}

// runSetupCmd generates (or regenerates) the CA certificate.
func runSetupCmd(cmd *cobra.Command, args []string) error {
	resolvedCADir, err := resolvePath(caDir)
	if err != nil {
		return fmt.Errorf("resolving --ca-dir: %w", err)
	}

	// Use a minimal logger for setup (no debug noise by default).
	logger := buildLogger(verbose)
	caManager := ca.NewManager(resolvedCADir, logger)

	// Check for an existing CA and bail unless --force is set.
	if caManager.Exists() && !forceSetup {
		certPath := caManager.CertPath()
		fmt.Printf("CA certificate already exists at:\n  %s\n\n", certPath)
		fmt.Println("Use --force to regenerate it.")
		return nil
	}

	// Generate (or regenerate) the CA.
	_, err = caManager.GenerateCA(forceSetup)
	if err != nil {
		return fmt.Errorf("generating CA: %w", err)
	}

	certPath := caManager.CertPath()
	fmt.Printf("✓ CA certificate generated: %s\n", certPath)
	fmt.Printf("✓ CA key written:           %s\n", caManager.KeyPath())
	fmt.Println()

	ca.PrintTrustInstructions(os.Stdout, certPath)
	return nil
}

// resolveEnvVarFlags is the PersistentPreRunE hook that reads STELLARIS_AUTH_*
// environment variables as fallbacks for flags that were not explicitly set on
// the command line.
func resolveEnvVarFlags(cmd *cobra.Command, args []string) error {
	// STELLARIS_AUTH_PORT → --port (only if the flag was not explicitly set).
	if !cmd.Flags().Changed("port") {
		if envPort := os.Getenv("STELLARIS_AUTH_PORT"); envPort != "" {
			p, err := strconv.Atoi(envPort)
			if err != nil {
				return fmt.Errorf("invalid STELLARIS_AUTH_PORT=%q: %w", envPort, err)
			}
			port = p
		}
	}

	// STELLARIS_AUTH_VERBOSE → --verbose ("1" or "true" are truthy).
	if !cmd.Flags().Changed("verbose") {
		if envVerbose := os.Getenv("STELLARIS_AUTH_VERBOSE"); envVerbose != "" {
			verbose = envVerbose == "1" || strings.EqualFold(envVerbose, "true")
		}
	}

	// STELLARIS_AUTH_INSECURE → --insecure ("1" or "true" are truthy).
	if !cmd.Flags().Changed("insecure") {
		if envInsecure := os.Getenv("STELLARIS_AUTH_INSECURE"); envInsecure != "" {
			insecure = envInsecure == "1" || strings.EqualFold(envInsecure, "true")
		}
	}

	// STELLARIS_AUTH_CA_DIR → --ca-dir (only if the flag was not explicitly set).
	if !cmd.Flags().Changed("ca-dir") {
		if envCADir := os.Getenv("STELLARIS_AUTH_CA_DIR"); envCADir != "" {
			caDir = envCADir
		}
	}

	// Default caDir if still empty after flag + env resolution.
	if caDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("determining home directory: %w", err)
		}
		caDir = filepath.Join(home, ".stellaris-auth", "ca")
	}

	return nil
}

// buildLogger returns a slog.Logger that writes text to stderr.
// Debug level is enabled when verbose is true, Warn otherwise.
func buildLogger(verbose bool) *slog.Logger {
	level := slog.LevelWarn
	if verbose {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	}))
}

// resolvePath expands a leading ~/ to the user's home directory.
func resolvePath(p string) (string, error) {
	if strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("determining home directory: %w", err)
		}
		return filepath.Join(home, p[2:]), nil
	}
	return p, nil
}

// waitForProxy polls srv.Addr() until it returns a non-empty address or the
// timeout elapses, indicating the proxy's TCP listener is bound and ready.
func waitForProxy(srv *proxy.Server, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if addr := srv.Addr(); addr != "" {
			return nil
		}
		time.Sleep(5 * time.Millisecond)
	}
	return fmt.Errorf("proxy did not start within %s", timeout)
}
