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
	_ "embed"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openpubkey/opkssh/policy"
	"github.com/openpubkey/opkssh/policy/files"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

//go:embed mocks/etc-passwd
var etcPasswdMock []byte

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

func SetupAuditCmdMocks(t *testing.T, etcPasswdContent string, providerContent string, systemPolicyContent string) AuditCmd {
	// Create in-memory filesystem
	fs := afero.NewMemMapFs()

	err := afero.WriteFile(fs, "/etc/passwd", []byte(etcPasswdContent), 0640)
	require.NoError(t, err)

	// Create provider file
	err = afero.WriteFile(fs, "/etc/opk/providers", []byte(providerContent), 0640)
	require.NoError(t, err)

	// Create auth_id file
	err = afero.WriteFile(fs, "/etc/opk/auth_id", []byte(systemPolicyContent), 0640)
	require.NoError(t, err)

	// Mock provider loader
	mockLoader := &MockProviderLoader{
		content: providerContent,
		t:       t,
	}

	// Create audit command
	return AuditCmd{
		Fs:             fs,
		ProviderLoader: mockLoader,
		filePermsChecker: files.PermsChecker{
			Fs: fs,
			CmdRunner: func(name string, arg ...string) ([]byte, error) {
				return []byte("root" + " " + "opkssh"), nil
			},
		},
		ProviderPath: "/etc/opk/providers",
		PolicyPath:   "/etc/opk/auth_id",
	}
}

func TestAuditCmd(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                   string
		providerContent        string
		SystemPolicyContent    string
		currentUsername        string
		hasUserAuthID          bool
		jsonOutput             bool
		expectedSuccessCount   int
		expectedWarningCount   int
		expectedErrorCount     int
		expectedStdOutContains []string
		expectedStdErrContains []string
	}{
		{
			name: "Valid configuration",
			providerContent: `https://accounts.google.com google-client-id 24h
		https://auth.example.com example-client-id 24h`,
			SystemPolicyContent: `root alice@mail.com https://accounts.google.com
		dev bob@example.com https://auth.example.com`,
			currentUsername:      "testuser",
			hasUserAuthID:        false,
			expectedSuccessCount: 2,
			expectedWarningCount: 0, // google alias usage
			expectedErrorCount:   0,
			expectedStdOutContains: []string{
				"[OK] SUCCESS",
				"Total Entries Tested:  2",
			},
			expectedStdErrContains: []string{
				"validating /etc/opk/auth_id",
			},
		},
		{
			name:            "Protocol mismatch error",
			providerContent: `https://accounts.google.com google-client-id 24h`,
			SystemPolicyContent: `root alice@mail.com https://accounts.google.com
		root bob@mail.com http://accounts.google.com`,
			currentUsername:      "testuser",
			hasUserAuthID:        false,
			expectedSuccessCount: 1,
			expectedWarningCount: 0,
			expectedErrorCount:   1,
			expectedStdOutContains: []string{
				"[ERR] ERROR",
				"issuer not found",
			},
		},
		{
			name:                 "Missing provider",
			providerContent:      `https://accounts.google.com google-client-id 24h`,
			SystemPolicyContent:  `root alice@mail.com https://notfound.com`,
			currentUsername:      "testuser",
			hasUserAuthID:        false,
			expectedSuccessCount: 0,
			expectedWarningCount: 0,
			expectedErrorCount:   1,
			expectedStdOutContains: []string{
				"[ERR] ERROR",
				"issuer not found",
			},
		},
		{
			name:                 "Empty auth_id file",
			providerContent:      `https://accounts.google.com google-client-id 24h`,
			SystemPolicyContent:  "",
			currentUsername:      "testuser",
			hasUserAuthID:        false,
			expectedSuccessCount: 0,
			expectedWarningCount: 0,
			expectedErrorCount:   0,
			expectedStdOutContains: []string{
				"Total Entries Tested:  0",
			},
			expectedStdErrContains: []string{
				"no policy entries",
				"validating /etc/opk/auth_id",
			},
		},
		{
			name: "Json Output (happy path)",
			providerContent: `https://accounts.google.com google-client-id 24h
		https://auth.example.com example-client-id 24h`,
			SystemPolicyContent: `root alice@mail.com google
		dev bob@example.com https://auth.example.com`,
			currentUsername:        "testuser",
			hasUserAuthID:          false,
			jsonOutput:             true,
			expectedSuccessCount:   2,
			expectedWarningCount:   0,
			expectedErrorCount:     1, // google alias usage
			expectedStdOutContains: []string{"{\n  \"ok\": false,\n  \"username\": \"testuser\""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdOut := &bytes.Buffer{}
			errOut := &bytes.Buffer{}

			// Create audit command
			auditCmd := SetupAuditCmdMocks(t, string(etcPasswdMock),
				tt.providerContent, tt.SystemPolicyContent)
			auditCmd.Out = stdOut
			auditCmd.ErrOut = errOut

			auditCmd.CurrentUsername = tt.currentUsername
			auditCmd.JsonOutput = tt.jsonOutput

			// Run audit
			runErr := auditCmd.Run("test_version")

			// Capture outputs
			output := stdOut.String()
			errOutput := errOut.String()

			// Verify exit code is 0 for successful audit (no errors/warnings)
			if tt.expectedErrorCount == 0 && tt.expectedWarningCount == 0 {
				require.NoError(t, runErr, "Expected no error when audit finds no errors or warnings")
			} else if tt.expectedErrorCount > 0 || tt.expectedWarningCount > 0 {
				require.Error(t, runErr, "Expected error when audit finds errors or warnings")
			}

			// Normalize paths in output for cross-platform compatibility
			normalizedOutput := strings.ReplaceAll(output, string(filepath.Separator), "/")
			normalizedErrOutput := strings.ReplaceAll(errOutput, string(filepath.Separator), "/")

			// Verify stdOut and stdErr contains expected strings
			for _, expected := range tt.expectedStdOutContains {
				require.Contains(t, normalizedOutput, expected, "Expected stdOut to contain: %s", expected)
			}
			for _, expected := range tt.expectedStdErrContains {
				require.Contains(t, normalizedErrOutput, expected, "Expected stdErr to contain: %s", expected)
			}
		})
	}
}

func TestAuditCmdJson(t *testing.T) {
	tests := []struct {
		name                string
		passwordContent     string
		providerContent     string
		systemPolicyContent string
		currentUsername     string

		// Expected results
		expOk                      bool
		expUsername                string
		expOsInfo                  string
		expSystemPolicyFileRowsLen int
	}{
		{
			name:            "Ok configuration",
			passwordContent: string(etcPasswdMock),
			providerContent: `https://accounts.google.com google-client-id 24h
		https://auth.example.com example-client-id 24h`,
			systemPolicyContent: `root alice@mail.com https://accounts.google.com
		dev bob@example.com https://auth.example.com`,
			currentUsername:            "testuser",
			expOk:                      true,
			expUsername:                "testuser",
			expSystemPolicyFileRowsLen: 2,
		},
		{
			name:            "Bad provider configuration",
			passwordContent: string(etcPasswdMock),
			providerContent: `corrupted content`,
			systemPolicyContent: `root alice@mail.com https://accounts.google.com
		dev bob@example.com https://auth.example.com`,
			currentUsername:            "testuser",
			expOk:                      false,
			expUsername:                "testuser",
			expSystemPolicyFileRowsLen: 2,
		},
		{
			name:            "Bad system policy",
			passwordContent: string(etcPasswdMock),
			providerContent: `https://accounts.google.com google-client-id 24h
		https://auth.example.com example-client-id 24h`,
			systemPolicyContent:        "corrupted line\n'''",
			currentUsername:            "testuser",
			expOk:                      false,
			expUsername:                "testuser",
			expSystemPolicyFileRowsLen: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create audit command
			stdOut := &bytes.Buffer{}
			errOut := &bytes.Buffer{}

			// Create audit command
			auditCmd := SetupAuditCmdMocks(t, tt.passwordContent,
				tt.providerContent, tt.systemPolicyContent)
			auditCmd.Out = stdOut
			auditCmd.ErrOut = errOut
			auditCmd.CurrentUsername = tt.currentUsername

			totalResults, err := auditCmd.Audit("test_version")
			require.NoError(t, err, "Expected no error during audit")
			require.NotNil(t, totalResults, "Expected totalResults to be non-nil")

			require.Equal(t, tt.expOk, totalResults.Ok)
			require.Equal(t, tt.expUsername, totalResults.Username)
			require.NotEmpty(t, totalResults.OsInfo)
			require.Equal(t, tt.expSystemPolicyFileRowsLen, len(totalResults.SystemPolicyFile.Rows))
		})
	}
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

	errorResult := validator.ValidateEntry("root", "alice@mail.com", "https://notfound.com", 1)
	require.Equal(t, policy.StatusError, errorResult.Status)
}

func TestGetHomeDirsFromEtcPasswd(t *testing.T) {
	t.Parallel()

	etcPasswdRows := getHomeDirsFromEtcPasswd(string(etcPasswdMock))

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
