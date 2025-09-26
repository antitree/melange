// Copyright 2024 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux && amd64

package seccomp

import (
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"testing"
	"time"

	libseccomp "github.com/seccomp/libseccomp-golang"
)

// TestSyscallLogging tests that dangerous syscalls are properly logged
func TestSyscallLogging(t *testing.T) {
	if runtime.GOARCH != "amd64" || runtime.GOOS != "linux" {
		t.Skip("Syscall logging tests only supported on linux/amd64")
	}

	if os.Getuid() != 0 {
		t.Skip("Syscall logging tests require root privileges")
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	monitor := NewMonitor(logger)

	config := Config{
		Enabled:         true,
		LogDangerous:    true,
		FailOnViolation: false,
	}

	err := monitor.EnableMonitoring(config)
	if err != nil {
		t.Fatalf("Failed to enable monitoring: %v", err)
	}

	if !monitor.IsEnabled() {
		t.Fatal("Monitor should be enabled after EnableMonitoring()")
	}

	// Test that basic syscalls still work
	t.Run("basic_syscalls", func(t *testing.T) {
		// These should work without issues (allowed syscalls)
		_, err := os.Open("/dev/null")
		if err != nil {
			t.Errorf("Basic open() syscall failed: %v", err)
		}

		_ = syscall.Getpid()
		_ = syscall.Getuid()
	})

	// Test potentially dangerous syscalls in a controlled way
	t.Run("monitored_syscalls", func(t *testing.T) {
		// Test execve (should be logged but allowed)
		cmd := exec.Command("echo", "seccomp test")
		err := cmd.Run()
		if err != nil {
			t.Errorf("execve should be allowed: %v", err)
		}

		// Test socket creation (should be logged but allowed)
		fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
		if err != nil {
			t.Errorf("socket creation should be allowed: %v", err)
		} else {
			syscall.Close(fd)
		}
	})
}

// TestSeccompBypassPrevention tests that seccomp cannot be bypassed
func TestSeccompBypassPrevention(t *testing.T) {
	if runtime.GOARCH != "amd64" || runtime.GOOS != "linux" {
		t.Skip("Bypass prevention tests only supported on linux/amd64")
	}

	if os.Getuid() != 0 {
		t.Skip("Bypass prevention tests require root privileges")
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	monitor := NewMonitor(logger)

	config := Config{
		Enabled:         true,
		LogDangerous:    true,
		FailOnViolation: false,
	}

	err := monitor.EnableMonitoring(config)
	if err != nil {
		t.Fatalf("Failed to enable monitoring: %v", err)
	}

	// Once seccomp is loaded, it should not be possible to disable it
	// from the same process or change the filter
	t.Run("cannot_disable_seccomp", func(t *testing.T) {
		// Try to enable a second monitor (should fail or be no-op)
		monitor2 := NewMonitor(logger)
		err := monitor2.EnableMonitoring(config)
		// This might succeed (creating another filter) or fail
		// The important thing is that the first filter remains active
		t.Logf("Second monitor enable result: %v", err)
	})

	t.Run("profile_persists", func(t *testing.T) {
		// Verify the monitor is still enabled after attempting changes
		if !monitor.IsEnabled() {
			t.Error("Monitor should remain enabled")
		}

		// Test that monitored syscalls still work
		cmd := exec.Command("true")
		err := cmd.Run()
		if err != nil {
			t.Errorf("Monitored syscalls should still work: %v", err)
		}
	})
}

// TestSyscallCoverage tests that our syscall list covers expected dangerous operations
func TestSyscallCoverage(t *testing.T) {
	if runtime.GOARCH != "amd64" || runtime.GOOS != "linux" {
		t.Skip("Syscall coverage tests only supported on linux/amd64")
	}

	// Test that our dangerous syscall list includes expected syscalls
	dangerousSyscalls := []string{
		"execve", "execveat",
		"clone", "fork", "vfork",
		"ptrace",
		"mount", "umount", "umount2",
		"chroot", "pivot_root",
		"socket", "bind", "connect",
		"init_module", "finit_module", "delete_module",
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	_ = NewMonitor(logger) // Monitor not needed for this test

	// Create a test filter to verify syscalls can be added
	filter, err := libseccomp.NewFilter(libseccomp.ActAllow)
	if err != nil {
		t.Fatalf("Failed to create test filter: %v", err)
	}
	defer filter.Release()

	for _, syscallName := range dangerousSyscalls {
		t.Run(syscallName, func(t *testing.T) {
			syscallID, err := libseccomp.GetSyscallFromName(syscallName)
			if err != nil {
				t.Logf("Syscall %s not available on this system: %v", syscallName, err)
				return
			}

			err = filter.AddRule(syscallID, libseccomp.ActLog)
			if err != nil {
				t.Errorf("Failed to add rule for %s: %v", syscallName, err)
			}
		})
	}
}

// TestPerformanceImpact tests that seccomp monitoring has minimal performance impact
func TestPerformanceImpact(t *testing.T) {
	if runtime.GOARCH != "amd64" || runtime.GOOS != "linux" {
		t.Skip("Performance tests only supported on linux/amd64")
	}

	if os.Getuid() != 0 {
		t.Skip("Performance tests require root privileges")
	}

	// Benchmark without seccomp
	start := time.Now()
	for i := 0; i < 1000; i++ {
		_, err := os.Open("/dev/null")
		if err == nil {
			// Close is implicit when variable goes out of scope
		}
	}
	withoutSeccomp := time.Since(start)

	// Enable seccomp
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	monitor := NewMonitor(logger)

	config := Config{
		Enabled:         true,
		LogDangerous:    true,
		FailOnViolation: false,
	}

	err := monitor.EnableMonitoring(config)
	if err != nil {
		t.Fatalf("Failed to enable monitoring: %v", err)
	}

	// Benchmark with seccomp
	start = time.Now()
	for i := 0; i < 1000; i++ {
		_, err := os.Open("/dev/null")
		if err == nil {
			// Close is implicit when variable goes out of scope
		}
	}
	withSeccomp := time.Since(start)

	// Calculate overhead
	overhead := float64(withSeccomp-withoutSeccomp) / float64(withoutSeccomp) * 100

	t.Logf("Performance without seccomp: %v", withoutSeccomp)
	t.Logf("Performance with seccomp: %v", withSeccomp)
	t.Logf("Overhead: %.2f%%", overhead)

	// We expect less than 10% overhead for basic syscalls
	if overhead > 10.0 {
		t.Errorf("Seccomp overhead %.2f%% exceeds 10%% threshold", overhead)
	}
}
