// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 HyvMind.io

//go:build !windows

package runner

import (
	"os"
	"os/signal"
	"syscall"
)

// setupSignalForwarding registers a goroutine that forwards SIGINT and SIGTERM
// to the child process. The returned cancel function stops forwarding and must
// be called after the child exits.
func setupSignalForwarding(r *Runner) func() {
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		defer signal.Stop(ch)
		for {
			select {
			case sig := <-ch:
				_ = r.Signal(sig)
			case <-done:
				return
			}
		}
	}()
	return func() { close(done) }
}
