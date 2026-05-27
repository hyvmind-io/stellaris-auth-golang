// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 HyvMind.io

package runner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
)

// Config holds configuration for running a child process.
type Config struct {
	// Binary is "tofu" or "terraform" — resolved via LookPath.
	Binary string

	// Args are the arguments to pass to the binary (e.g., ["init", "--upgrade"]).
	Args []string

	// ProxyAddr is the HTTP proxy address, e.g., "http://127.0.0.1:8080".
	ProxyAddr string

	// CAFile is the absolute path to the CA certificate PEM file.
	CAFile string

	// Logger for structured output.
	Logger *slog.Logger
}

// Runner manages the lifecycle of a tofu/terraform child process.
type Runner struct {
	cfg     Config
	binPath string
	args    []string // alias-prefix args (if any) followed by cfg.Args
	cmd     *exec.Cmd
}

// New resolves the binary and returns a Runner ready to use. The name in
// cfg.Binary may be a real executable on PATH or one of the user's interactive
// shell aliases (e.g. "tg" -> "terragrunt"); see resolveBinary. Any leading
// arguments contributed by an alias are prepended to cfg.Args. Returns an error
// if the name resolves to neither a binary nor a usable alias.
func New(cfg Config) (*Runner, error) {
	binPath, prefixArgs, err := resolveBinary(cfg.Binary, cfg.Logger)
	if err != nil {
		return nil, err
	}

	args := cfg.Args
	if len(prefixArgs) > 0 {
		args = append(append([]string{}, prefixArgs...), cfg.Args...)
	}

	return &Runner{
		cfg:     cfg,
		binPath: binPath,
		args:    args,
	}, nil
}

// Start forks the child process, wiring up stdin/stdout/stderr directly and
// injecting proxy environment variables.
func (r *Runner) Start() error {
	//nolint:gosec // G204: executing the user-specified binary is this tool's entire purpose.
	r.cmd = exec.Command(r.binPath, r.args...)
	r.cmd.Env = buildChildEnv(os.Environ(), r.cfg.ProxyAddr, r.cfg.CAFile)
	r.cmd.Stdout = os.Stdout
	r.cmd.Stderr = os.Stderr
	r.cmd.Stdin = os.Stdin

	r.cfg.Logger.Info("starting child process",
		slog.String("binary", r.binPath),
		slog.Any("args", r.args),
	)

	if err := r.cmd.Start(); err != nil {
		return fmt.Errorf("runner: failed to start %q: %w", r.binPath, err)
	}
	return nil
}

// Wait blocks until the child process exits and returns its exit code.
// A clean exit returns (0, nil). A non-zero exit code from the child returns
// (code, nil) — the caller decides whether that is an error. An unexpected
// wait failure returns (1, err).
func (r *Runner) Wait() (int, error) {
	err := r.cmd.Wait()
	if err == nil {
		return 0, nil
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), nil
	}

	return 1, err
}

// Signal sends sig to the child process. If the process has already exited
// the error is silently ignored.
func (r *Runner) Signal(sig os.Signal) error {
	if r.cmd == nil || r.cmd.Process == nil {
		return nil
	}
	err := r.cmd.Process.Signal(sig)
	// Ignore "os: process already finished"
	if err != nil && errors.Is(err, os.ErrProcessDone) {
		return nil
	}
	return err
}

// Run is the primary entry point. It starts the child, sets up OS signal
// forwarding, waits for the child to exit, tears down signal forwarding, and
// returns the exit code.
func (r *Runner) Run(ctx context.Context) (int, error) {
	if err := r.Start(); err != nil {
		return 1, err
	}

	cancelSignals := setupSignalForwarding(r)

	code, err := r.Wait()

	cancelSignals()

	r.cfg.Logger.Info("child process exited",
		slog.String("binary", r.binPath),
		slog.Int("exit_code", code),
	)

	return code, err
}

// buildChildEnv builds the environment slice for the child process. It takes
// the parent's environment, strips any existing entries for the proxy/CA keys
// (case-insensitive), then appends the override entries derived from proxyAddr
// and caFile.
func buildChildEnv(parentEnv []string, proxyAddr, caFile string) []string {
	overrideKeys := []string{
		"HTTPS_PROXY",
		"HTTP_PROXY",
		"SSL_CERT_FILE",
		"NODE_EXTRA_CA_CERTS",
	}

	// Build a set of uppercase keys to filter.
	filterSet := make(map[string]struct{}, len(overrideKeys))
	for _, k := range overrideKeys {
		filterSet[strings.ToUpper(k)] = struct{}{}
	}

	// Copy parent env, skipping any keys we are about to override.
	filtered := make([]string, 0, len(parentEnv)+len(overrideKeys))
	for _, entry := range parentEnv {
		idx := strings.IndexByte(entry, '=')
		if idx < 0 {
			filtered = append(filtered, entry)
			continue
		}
		key := strings.ToUpper(entry[:idx])
		if _, skip := filterSet[key]; !skip {
			filtered = append(filtered, entry)
		}
	}

	// Append the override entries.
	filtered = append(filtered,
		"HTTPS_PROXY="+proxyAddr,
		"HTTP_PROXY="+proxyAddr,
		"SSL_CERT_FILE="+caFile,
		"NODE_EXTRA_CA_CERTS="+caFile,
	)

	return filtered
}
