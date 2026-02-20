//go:build windows

package runner

import (
	"os"
	"os/signal"
)

// setupSignalForwarding registers a goroutine that forwards os.Interrupt to
// the child process on Windows. The returned cancel function stops forwarding
// and must be called after the child exits.
func setupSignalForwarding(r *Runner) func() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	done := make(chan struct{})
	go func() {
		defer signal.Stop(ch)
		select {
		case <-ch:
			if r.cmd != nil && r.cmd.Process != nil {
				_ = r.cmd.Process.Kill()
			}
		case <-done:
		}
	}()
	return func() { close(done) }
}
