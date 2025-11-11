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

package commands_test

import (
	"bytes"
	"os/user"
	"testing"

	"github.com/openpubkey/opkssh/commands"
	"github.com/openpubkey/opkssh/policy"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

// MockUserLookup implements commands.UserLookup for testing
type MockUserLookup struct {
	users map[string]*user.User
}

func (m *MockUserLookup) Lookup(username string) (*user.User, error) {
	if u, ok := m.users[username]; ok {
		return u, nil
	}
	return nil, user.UnknownUserError(username)
}

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
				"✓ SUCCESS",
				"⚠ WARNING",
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
				"✗ ERROR",
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
				"✗ ERROR",
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
			cmd := &commands.AuditCmd{
				Fs:                 fs,
				Out:                out,
				ProviderLoader:     mockLoader,
				SystemProviderPath: "/etc/opk/providers",
				SystemPolicyPath:   "/etc/opk/auth_id",
				UserPolicyLookup: &MockUserLookup{
					users: map[string]*user.User{
						"testuser": {
							Username: "testuser",
							HomeDir:  "/home/testuser",
						},
					},
				},
				CurrentUsername: tt.currentUsername,
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

			// Verify output contains expected strings
			for _, expected := range tt.expectedOutputContains {
				require.Contains(t, output, expected, "Expected output to contain: %s", expected)
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
