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

package plugins

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/openpubkey/opkssh/policy/files"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

func TestLoadPolicyPlugins(t *testing.T) {
	tests := []struct {
		name             string
		files            map[string]string // File name to content mapping
		expectedCount    int
		expectErrorCount int
		expectError      bool
	}{
		{
			name: "Valid plugin config",
			files: map[string]string{
				"valid_policy.yml": `
name: Example Policy Command
enforce_providers: true
command: /usr/bin/local/opk/policy-cmd %sub %iss %aud`,
			},
			expectedCount:    1,
			expectErrorCount: 0,
		},
		{
			name: "Invalid plugin configs (missing required fields)",
			files: map[string]string{
				"invalid_policy1.yml": `
name: Invalid Policy Command
command:
enforce_providers: true
`,
				"invalid_policy2.yml": `
name:
command:
enforce_providers: true
`,
			},
			expectedCount:    2,
			expectErrorCount: 2,
		},
		{
			name: "Mixed valid and invalid plugin config",
			files: map[string]string{
				"valid_policy.yml": `
name: Example Policy Command
enforce_providers: true
command: /usr/bin/local/opk/policy-cmd %sub %iss %aud
`,
				"invalid_policy.yml": `
name: Invalid Policy Command
enforce_providers: true
invalid_field: true
`,
			},
			expectedCount:    2,
			expectErrorCount: 1,
		},
		{
			name: "Corrupt YAML file",
			files: map[string]string{
				"corrupt_policy.yml": `{`,
			},
			expectedCount:    1,
			expectErrorCount: 1,
		},

		{
			name:             "No files in directory",
			files:            map[string]string{},
			expectedCount:    0,
			expectErrorCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockFs := afero.NewMemMapFs()
			tempDir, _ := afero.TempDir(mockFs, "", "policy_test")

			enforcer := &PolicyPluginEnforcer{
				Fs: mockFs,
				permChecker: files.PermsChecker{
					Fs: mockFs,
					CmdRunner: func(name string, arg ...string) ([]byte, error) {
						return []byte("root" + " " + "group"), nil
					},
				},
			}

			// Write test config plugins files
			for fileName, content := range tt.files {
				err := afero.WriteFile(mockFs, filepath.Join(tempDir, fileName), []byte(content), 0640)
				require.NoError(t, err)
			}

			// Load policy commands
			pluginResults, err := enforcer.loadPlugins(tempDir)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)

				require.Len(t, pluginResults, tt.expectedCount)
				require.Len(t, pluginResults.Errors(), tt.expectErrorCount, "Expected number of errors does not match actual number of errors")
			}
		})
	}
}

func TestPolicyPluginsWithMock(t *testing.T) {
	mockCmdExecutor := func(name string, arg ...string) ([]byte, error) {
		if "/usr/bin/local/opk/policy-cmd" == name {
			if len(arg) != 3 {
				return nil, fmt.Errorf("expected 3 arguments, got %d", len(arg))
			} else if arg[0] == "https://example.com" && arg[1] == "1234" && arg[2] == "abcd" {
				return []byte("allowed"), nil
			} else if arg[0] == "https://example.com" && arg[1] == "sub with spaces" && arg[2] == "abcd" {
				return []byte("allowed"), nil
			} else if arg[0] == "https://example.com" && arg[1] == "sub\"withquote" && arg[2] == "abcd" {
				return []byte("allowed"), nil
			} else {
				// Designed to test an command that doesn't output an error but returns deny. Deny should return an error as well.
				return []byte("deny"), nil
			}
		}
		return nil, fmt.Errorf("command '%s' not found", name)
	}

	validPluginConfigFile := map[string]string{
		"valid_policy.yml": `
name: Example Policy Command
enforce_providers: true
command: /usr/bin/local/opk/policy-cmd %iss% %sub% %aud%`}

	missingCommandConfigFile := map[string]string{"missing-command.yml": `
name: Example Policy Command
enforce_providers: true
command: /usr/bin/local/opk/missing-cmd %iss% %sub% %aud%`}

	InvalidCommandConfigFile := map[string]string{"missing-command.yml": `
name: Example Policy Command
enforce_providers: true
command: /usr/bin/local/opk/missing-cmd %iss% %sub% %aud%"`}

	tests := []struct {
		name                string
		tokens              map[string]string
		files               map[string]string // File name to content mapping
		CmdExecutor         func(name string, arg ...string) ([]byte, error)
		expectedAllowed     bool
		expectedResultCount int
		expectErrorCount    int
		errorExpected       string
	}{
		{
			name: "Valid plugin config",
			tokens: map[string]string{
				"%iss%": "https://example.com",
				"%sub%": "1234",
				"%aud%": "abcd",
			},
			files:               validPluginConfigFile,
			CmdExecutor:         mockCmdExecutor,
			expectedAllowed:     true,
			expectedResultCount: 1,
			expectErrorCount:    0,
		},
		{
			name: "Plugin config not found",
			tokens: map[string]string{
				"%iss%": "https://example.com",
				"%sub%": "1234",
				"%aud%": "abcd",
			},
			files:               missingCommandConfigFile,
			CmdExecutor:         mockCmdExecutor,
			expectedAllowed:     false,
			expectedResultCount: 1,
			expectErrorCount:    1,
			errorExpected:       "file does not exist",
		},
		{
			name: "Check we handle spaces in claims",
			tokens: map[string]string{
				"%iss%": "https://example.com",
				"%sub%": "sub with spaces",
				"%aud%": "abcd",
			},
			files:               validPluginConfigFile,
			CmdExecutor:         mockCmdExecutor,
			expectedAllowed:     true,
			expectedResultCount: 1,
			expectErrorCount:    0,
			errorExpected:       "",
		},
		{
			name: "Test we handle quotes in tokens",
			tokens: map[string]string{
				"%iss%": "https://example.com",
				"%sub%": `sub"withquote`,
				"%aud%": "abcd",
			},
			files:               validPluginConfigFile,
			CmdExecutor:         mockCmdExecutor,
			expectedAllowed:     true,
			expectedResultCount: 1,
			expectErrorCount:    0,
			errorExpected:       "",
		},
		{
			name: "Policy command denial",
			tokens: map[string]string{
				"%iss%": "https://example.com",
				"%sub%": "wrong",
				"%aud%": "abcd",
			},
			files:               validPluginConfigFile,
			CmdExecutor:         mockCmdExecutor,
			expectedAllowed:     false,
			expectedResultCount: 1,
			expectErrorCount:    0,
			errorExpected:       "",
		},
		{
			name: "Policy invalid command template",
			tokens: map[string]string{
				"%iss%": "https://example.com",
				"%sub%": "1234",
				"%aud%": "abcd",
			},
			files:               InvalidCommandConfigFile,
			CmdExecutor:         mockCmdExecutor,
			expectedAllowed:     false,
			expectedResultCount: 1,
			expectErrorCount:    1,
			errorExpected:       "failed to parse command field: Unterminated double-quoted string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockFs := afero.NewMemMapFs()
			tempDir, _ := afero.TempDir(mockFs, "", "policy_test")

			// Write test config plugins files
			for fileName, content := range tt.files {
				err := afero.WriteFile(mockFs, filepath.Join(tempDir, fileName), []byte(content), 0640)
				require.NoError(t, err)
			}

			// Create the command we are going to call. It needs to be exist but it can be empty.
			err := afero.WriteFile(mockFs, filepath.Join("/usr/bin/local/opk/policy-cmd"), []byte(""), 0755)
			require.NoError(t, err)

			enforcer := &PolicyPluginEnforcer{
				Fs:          mockFs,
				cmdExecutor: tt.CmdExecutor,
				permChecker: files.PermsChecker{
					Fs: mockFs,
					CmdRunner: func(name string, arg ...string) ([]byte, error) {
						return []byte("root" + " " + "group"), nil
					},
				},
			}
			res, err := enforcer.checkPolicies(tempDir, tt.tokens)
			require.NoError(t, err)
			require.Len(t, res, tt.expectedResultCount)
			require.Len(t, res.Errors(), tt.expectErrorCount, "Errors in result does not match expected number of errors")
			require.Equal(t, tt.expectedAllowed, res.Allowed())

			if tt.errorExpected != "" {
				// Our error contains checking only works if there is 1 result
				require.Len(t, res, 1)
				require.ErrorContains(t, res[0].Error, tt.errorExpected)
			}
		})
	}
}

func TestPluginPanics(t *testing.T) {
	result := &PluginResult{
		Allowed:      true,
		PolicyOutput: "denied",
		Path:         "/etc/opk/plugin.yml",
	}
	results := PluginResults{result}

	require.PanicsWithValue(t,
		fmt.Sprintf(
			"Danger!!! Policy plugin command (%s) returned 'allowed' but the plugin command did not approve. If you encounter this, report this as a vulnerability.",
			result.Path,
		),
		func() {
			_ = results.Allowed()
		},
	)
}
