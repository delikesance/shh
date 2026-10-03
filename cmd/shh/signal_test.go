package main

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestSignalShutdown(t *testing.T) {
	// Build or locate binary for signal testing
	binPath := filepath.Join(t.TempDir(), "shh_test_bin")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("failed to build test binary: %v", err)
	}

	signals := []struct {
		name string
		sig  syscall.Signal
	}{
		{name: "SIGINT", sig: syscall.SIGINT},
		{name: "SIGTERM", sig: syscall.SIGTERM},
	}

	for _, tc := range signals {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(binPath, "-b", "127.0.0.1", "-p", "0")
			cmd.Env = append(os.Environ(), "SHH_HOST_KEY=")

			stderr, err := cmd.StderrPipe()
			if err != nil {
				t.Fatalf("failed to get stderr pipe: %v", err)
			}

			if err := cmd.Start(); err != nil {
				t.Fatalf("failed to start process: %v", err)
			}

			scanner := bufio.NewScanner(stderr)
			started := make(chan struct{})
			var logs []string

			go func() {
				for scanner.Scan() {
					text := scanner.Text()
					logs = append(logs, text)
					if strings.Contains(text, "Encrypted chat daemon listening") {
						select {
						case <-started:
						default:
							close(started)
						}
					}
				}
			}()

			select {
			case <-started:
			case <-time.After(3 * time.Second):
				_ = cmd.Process.Kill()
				t.Fatalf("daemon did not start in time. Logs: %v", logs)
			}

			// Send target signal
			if err := cmd.Process.Signal(tc.sig); err != nil {
				t.Fatalf("failed to send %s: %v", tc.name, err)
			}

			done := make(chan error, 1)
			go func() {
				done <- cmd.Wait()
			}()

			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("daemon did not exit cleanly on %s: %v. Logs: %v", tc.name, err, logs)
				}
			case <-time.After(4 * time.Second):
				_ = cmd.Process.Kill()
				t.Fatalf("daemon timed out waiting for shutdown on %s", tc.name)
			}
		})
	}
}
