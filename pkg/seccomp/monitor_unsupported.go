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

//go:build !linux || !amd64

package seccomp

import (
	"fmt"
	"log/slog"
	"runtime"
)

// Monitor provides a stub for unsupported architectures
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

// NewMonitor creates a new seccomp monitor stub
func NewMonitor(logger *slog.Logger) *Monitor {
	return &Monitor{
		enabled: false,
		logger:  logger,
	}
}

// IsSupported always returns an error on unsupported platforms
func IsSupported() error {
	return fmt.Errorf("seccomp monitoring not supported on %s/%s (requires linux/amd64)", runtime.GOOS, runtime.GOARCH)
}

// EnableMonitoring always returns an error on unsupported platforms
func (m *Monitor) EnableMonitoring(config Config) error {
	return IsSupported()
}

// IsEnabled always returns false on unsupported platforms
func (m *Monitor) IsEnabled() bool {
	return false
}

// GetStats returns minimal stats for unsupported platforms
func (m *Monitor) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"enabled":      false,
		"supported":    false,
		"architecture": runtime.GOARCH,
		"os":           runtime.GOOS,
	}
}
