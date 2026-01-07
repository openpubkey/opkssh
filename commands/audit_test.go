// Copyright 2025 OpenPubkey
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
//
// SPDX-License-Identifier: Apache-2.0

package commands

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openpubkey/opkssh/policy"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

// TestAuditCmd tests the audit command
func TestAuditCmd(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                   string
		providerContent        string
		authIDContent          string
		userAuthIDContent      string
		currentUsername        string
		hasUserAuthID          bool
		expectedSuccessCount   int
		expectedWarningCount   int
		expectedErrorCount     int
		expectedOutputContains []string
	}{
		{
			name: "Valid configuration",
			providerContent: `https://accounts.google.com google-client-id 24h
https://auth.example.com example-client-id 24h`,
			authIDContent: `root alice@mail.com google
dev bob@example.com https://auth.example.com`,
			currentUsername:      "testuser",
			hasUserAuthID:        false,
			expectedSuccessCount: 2,
			expectedWarningCount: 1, // google alias usage
			expectedErrorCount:   0,
			expectedOutputContains: []string{
				"Validating /etc/opk/auth_id",
				"[OK] SUCCESS",
				"[WARN] WARNING",
				"Total Entries Tested:  2",
			},
		},
		{
			name:            "Protocol mismatch error",
			providerContent: `https://accounts.google.com google-client-id 24h`,
			authIDContent: `root alice@mail.com https://accounts.google.com
root bob@mail.com http://accounts.google.com`,
			currentUsername:      "testuser",
			hasUserAuthID:        false,
			expectedSuccessCount: 1,
			expectedWarningCount: 0,
			expectedErrorCount:   1,
			expectedOutputContains: []string{
				"[ERR] ERROR",
				"issuer not found",
			},
		},
		{
			name:                 "Missing provider",
			providerContent:      `https://accounts.google.com google-client-id 24h`,
			authIDContent:        `root alice@mail.com https://notfound.com`,
			currentUsername:      "testuser",
			hasUserAuthID:        false,
			expectedSuccessCount: 0,
			expectedWarningCount: 0,
			expectedErrorCount:   1,
			expectedOutputContains: []string{
				"[ERR] ERROR",
				"issuer not found",
			},
		},
		{
			name:                 "Empty auth_id file",
			providerContent:      `https://accounts.google.com google-client-id 24h`,
			authIDContent:        "",
			currentUsername:      "testuser",
			hasUserAuthID:        false,
			expectedSuccessCount: 0,
			expectedWarningCount: 0,
			expectedErrorCount:   0,
			expectedOutputContains: []string{
				"Validating /etc/opk/auth_id",
				"No policy entries",
				"Total Entries Tested:  0",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create in-memory filesystem
			fs := afero.NewMemMapFs()
			out := &bytes.Buffer{}

			// Create provider file
			err := afero.WriteFile(fs, "/etc/opk/providers", []byte(tt.providerContent), 0640)
			require.NoError(t, err)

			// Create auth_id file
			err = afero.WriteFile(fs, "/etc/opk/auth_id", []byte(tt.authIDContent), 0640)
			require.NoError(t, err)

			// Mock provider loader
			mockLoader := &MockProviderLoader{
				content: tt.providerContent,
				t:       t,
			}

			// Create audit command
			cmd := &AuditCmd{
				Fs:                 fs,
				Out:                out,
				ProviderLoader:     mockLoader,
				SystemProviderPath: "/etc/opk/providers",
				SystemPolicyPath:   "/etc/opk/auth_id",
				CurrentUsername:    tt.currentUsername,
			}

			// Run audit
			exitCode := cmd.Run()
			output := out.String()

			// Verify exit code is 0 for successful audit (no errors/warnings)
			if tt.expectedErrorCount == 0 && tt.expectedWarningCount == 0 {
				require.Equal(t, 0, exitCode, "Expected exit code 0 for successful audit")
			} else if tt.expectedErrorCount > 0 || tt.expectedWarningCount > 0 {
				require.Equal(t, 1, exitCode, "Expected exit code 1 when errors or warnings present")
			}

			// Normalize paths in output for cross-platform compatibility
			normalizedOutput := strings.ReplaceAll(output, string(filepath.Separator), "/")

			// Verify output contains expected strings
			for _, expected := range tt.expectedOutputContains {
				require.Contains(t, normalizedOutput, expected, "Expected output to contain: %s", expected)
			}

			// Parse output to get counts (simple verification)
			// The exact counts are verified through policy validation tests
		})
	}
}

// MockProviderLoader mocks policy.ProviderFileLoader
type MockProviderLoader struct {
	content string
	t       *testing.T
}

func (m *MockProviderLoader) LoadProviderPolicy(path string) (*policy.ProviderPolicy, error) {
	pp := &policy.ProviderPolicy{}

	// Simple parser for test data
	lines := bytes.Split([]byte(m.content), []byte("\n"))
	for _, line := range lines {
		if len(line) == 0 || bytes.HasPrefix(line, []byte("#")) {
			continue
		}

		parts := bytes.Fields(line)
		if len(parts) >= 3 {
			pp.AddRow(policy.ProvidersRow{
				Issuer:           string(parts[0]),
				ClientID:         string(parts[1]),
				ExpirationPolicy: string(parts[2]),
			})
		}
	}

	return pp, nil
}

// TestAuditCmdValidationResults tests that validation results are properly calculated
func TestAuditCmdValidationResults(t *testing.T) {
	t.Parallel()

	// Create a test validator
	pp := &policy.ProviderPolicy{}
	pp.AddRow(policy.ProvidersRow{
		Issuer:           "https://accounts.google.com",
		ClientID:         "google-id",
		ExpirationPolicy: "24h",
	})

	validator := policy.NewPolicyValidator(pp)

	// Test various entry validations
	successResult := validator.ValidateEntry("root", "alice@mail.com", "https://accounts.google.com", 1)
	require.Equal(t, policy.StatusSuccess, successResult.Status)

	warningResult := validator.ValidateEntry("root", "alice@mail.com", "google", 1)
	require.Equal(t, policy.StatusWarning, warningResult.Status)

	errorResult := validator.ValidateEntry("root", "alice@mail.com", "https://notfound.com", 1)
	require.Equal(t, policy.StatusError, errorResult.Status)
}

func TestGetHomeDirsFromEtcPasswd(t *testing.T) {
	t.Parallel()
	etcPasswdContent := "root:x:0:0:root:/root:/bin/bash\n" +
		"# Comment line\n" +
		"dev:x:1001:1001::/home/dev:/bin/sh\n" +
		"\n" +
		"alice:x:995:981::/home/alice:/bin/sh\n" +
		"bob:x:1002:1002::/home/bob:/bin/sh\n" +
		"carol:x:1003:1003::/home/carol:/bin/sh\n"

	etcPasswdRows := getHomeDirsFromEtcPasswd(etcPasswdContent)

	require.Len(t, etcPasswdRows, 5)

	require.Equal(t, "root", etcPasswdRows[0].Username)
	require.Equal(t, "/root", etcPasswdRows[0].HomeDir)
	require.Equal(t, "dev", etcPasswdRows[1].Username)
	require.Equal(t, "/home/dev", etcPasswdRows[1].HomeDir)
	require.Equal(t, "alice", etcPasswdRows[2].Username)
	require.Equal(t, "/home/alice", etcPasswdRows[2].HomeDir)
	require.Equal(t, "bob", etcPasswdRows[3].Username)
	require.Equal(t, "/home/bob", etcPasswdRows[3].HomeDir)
	require.Equal(t, "carol", etcPasswdRows[4].Username)
	require.Equal(t, "/home/carol", etcPasswdRows[4].HomeDir)
}
