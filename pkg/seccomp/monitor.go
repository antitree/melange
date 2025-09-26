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
	"fmt"
	"log/slog"
	"runtime"

	libseccomp "github.com/seccomp/libseccomp-golang"
)

// Monitor provides seccomp-based syscall monitoring for melange builds
type Monitor struct {
	enabled bool
	logger  *slog.Logger
}

// Config holds seccomp monitoring configuration
type Config struct {
	Enabled         bool     `yaml:"enabled" json:"enabled"`
	LogDangerous    bool     `yaml:"log_dangerous" json:"log_dangerous"`
	AllowList       []string `yaml:"allow_list" json:"allow_list"`
	LogList         []string `yaml:"log_list" json:"log_list"`
	FailOnViolation bool     `yaml:"fail_on_violation" json:"fail_on_violation"`
}

// NewMonitor creates a new seccomp monitor
func NewMonitor(logger *slog.Logger) *Monitor {
	return &Monitor{
		enabled: false,
		logger:  logger,
	}
}

// IsSupported checks if seccomp monitoring is supported on this system
func IsSupported() error {
	if runtime.GOARCH != "amd64" {
		return fmt.Errorf("seccomp monitoring only supported on amd64, current arch: %s", runtime.GOARCH)
	}

	if runtime.GOOS != "linux" {
		return fmt.Errorf("seccomp monitoring only supported on linux, current OS: %s", runtime.GOOS)
	}

	// Check if libseccomp is available
	api, err := libseccomp.GetAPI()
	if err != nil {
		return fmt.Errorf("libseccomp not available: %w", err)
	}

	if api < 2 {
		return fmt.Errorf("libseccomp API version %d too old, need >= 2", api)
	}

	return nil
}

// EnableMonitoring activates seccomp-based syscall monitoring
func (m *Monitor) EnableMonitoring(config Config) error {
	if err := IsSupported(); err != nil {
		return fmt.Errorf("seccomp monitoring not supported: %w", err)
	}

	// Create seccomp filter with default allow action
	filter, err := libseccomp.NewFilter(libseccomp.ActAllow)
	if err != nil {
		return fmt.Errorf("failed to create seccomp filter: %w", err)
	}
	defer filter.Release()

	// Add rules for dangerous syscalls (log but allow)
	if err := m.addDangerousSyscallRules(filter); err != nil {
		return fmt.Errorf("failed to add dangerous syscall rules: %w", err)
	}

	// Load the filter
	if err := filter.Load(); err != nil {
		return fmt.Errorf("failed to load seccomp filter: %w", err)
	}

	m.enabled = true
	m.logger.Info("Seccomp monitoring enabled",
		"dangerous_syscalls_logged", true,
		"architecture", runtime.GOARCH)

	return nil
}

// addDangerousSyscallRules adds logging rules for dangerous syscalls
func (m *Monitor) addDangerousSyscallRules(filter *libseccomp.ScmpFilter) error {
	dangerousSyscalls := []string{
		// Process Control & Execution
		"execve", "execveat",
		"clone", "fork", "vfork",
		"ptrace",
		"setuid", "setgid", "setreuid", "setregid",
		"setresuid", "setresgid",
		"capset", "capget",

		// File System & Security
		"mount", "umount", "umount2",
		"chroot", "pivot_root",
		"swapon", "swapoff",
		"quotactl", "sysfs",
		"unshare", "setns",

		// Network Operations
		"socket", "bind", "connect",
		"listen", "accept", "accept4",
		"sendmsg", "recvmsg",
		"sendmmsg", "recvmmsg",

		// System Configuration
		"init_module", "finit_module", "delete_module",
		"reboot",
		"settimeofday", "adjtimex", "clock_settime",
	}

	for _, syscallName := range dangerousSyscalls {
		syscallID, err := libseccomp.GetSyscallFromName(syscallName)
		if err != nil {
			m.logger.Warn("Unknown syscall, skipping", "syscall", syscallName, "error", err)
			continue
		}

		// Add rule to log dangerous syscalls but still allow them
		err = filter.AddRule(syscallID, libseccomp.ActLog)
		if err != nil {
			return fmt.Errorf("failed to add rule for syscall %s: %w", syscallName, err)
		}
	}

	return nil
}

// IsEnabled returns whether monitoring is currently active
func (m *Monitor) IsEnabled() bool {
	return m.enabled
}

// GetStats returns monitoring statistics
func (m *Monitor) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"enabled":      m.enabled,
		"architecture": runtime.GOARCH,
		"os":           runtime.GOOS,
	}
}
