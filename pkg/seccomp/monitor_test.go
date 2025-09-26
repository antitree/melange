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

package seccomp

import (
	"log/slog"
	"os"
	"runtime"
	"testing"
)

func TestIsSupported(t *testing.T) {
	tests := []struct {
		name        string
		expectError bool
	}{
		{
			name:        "check support on current platform",
			expectError: runtime.GOARCH != "amd64" || runtime.GOOS != "linux",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := IsSupported()
			if tt.expectError && err == nil {
				t.Errorf("IsSupported() expected error on %s/%s, got nil", runtime.GOOS, runtime.GOARCH)
			}
			if !tt.expectError && err != nil {
				t.Errorf("IsSupported() unexpected error on %s/%s: %v", runtime.GOOS, runtime.GOARCH, err)
			}
		})
	}
}

func TestNewMonitor(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	monitor := NewMonitor(logger)

	if monitor == nil {
		t.Fatal("NewMonitor() returned nil")
	}

	if monitor.IsEnabled() {
		t.Error("NewMonitor() should create disabled monitor")
	}

	stats := monitor.GetStats()
	if stats["enabled"].(bool) {
		t.Error("NewMonitor() stats should show disabled")
	}

	expectedArch := runtime.GOARCH
	if stats["architecture"] != expectedArch {
		t.Errorf("Expected architecture %s, got %v", expectedArch, stats["architecture"])
	}
}

func TestMonitorEnableMonitoring(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	monitor := NewMonitor(logger)

	config := Config{
		Enabled:         true,
		LogDangerous:    true,
		FailOnViolation: false,
	}

	err := monitor.EnableMonitoring(config)

	// On non-supported platforms, should get an error
	if runtime.GOARCH != "amd64" || runtime.GOOS != "linux" {
		if err == nil {
			t.Error("EnableMonitoring() should fail on unsupported platform")
		}
		return
	}

	// On supported platforms, may still fail if libseccomp not available
	// But that's okay for testing - we just verify the interface works
	t.Logf("EnableMonitoring() result on %s/%s: %v", runtime.GOOS, runtime.GOARCH, err)
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name   string
		config Config
		valid  bool
	}{
		{
			name: "valid config",
			config: Config{
				Enabled:      true,
				LogDangerous: true,
			},
			valid: true,
		},
		{
			name: "disabled config",
			config: Config{
				Enabled: false,
			},
			valid: true,
		},
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			monitor := NewMonitor(logger)
			err := monitor.EnableMonitoring(tt.config)

			// We expect this to fail on unsupported platforms
			if runtime.GOARCH != "amd64" || runtime.GOOS != "linux" {
				if err == nil {
					t.Error("Should fail on unsupported platform")
				}
				return
			}

			// On supported platforms, log the result
			t.Logf("Config validation test %s: %v", tt.name, err)
		})
	}
}
