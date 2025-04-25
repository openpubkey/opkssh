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

	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

func TestLoadPolicyPlugins(t *testing.T) {
	tests := []struct {
		name                    string
		files                   map[string]string // File name to content mapping
		expectedCount           int
		expectResultsErrorCount int
		expectError             bool
	}{
		{
			name: "Valid plugin config",
			files: map[string]string{
				"valid_policy.yml": `
name: Example Policy Command
enforce_providers: true
command: /usr/bin/local/opk/policy-cmd %sub %iss %aud`,
			},
			expectedCount:           1,
			expectResultsErrorCount: 0,
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
			expectedCount:           2,
			expectResultsErrorCount: 2,
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
			expectedCount:           2,
			expectResultsErrorCount: 1,
		},
		{
			name:                    "No files in directory",
			files:                   map[string]string{},
			expectedCount:           0,
			expectResultsErrorCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockFs := afero.NewMemMapFs()
			tempDir, _ := afero.TempDir(mockFs, "", "policy_test")

			enforcer := &PolicyPluginEnforcer{
				Fs: mockFs,
			}

			// Write test config plugins files
			for fileName, content := range tt.files {
				err := afero.WriteFile(mockFs, filepath.Join(tempDir, fileName), []byte(content), 0644)
				require.NoError(t, err)
			}

			// Load policy commands
			pluginResults, err := enforcer.LoadPlugins(tempDir)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)

				require.Len(t, pluginResults, tt.expectedCount)
				require.Len(t, pluginResults.Errors(), tt.expectResultsErrorCount, "Expected number of errors does not match actual number of errors")
			}
		})
	}
}

func TestPolicyPluginsWithMock(t *testing.T) {

	mockCmdExecutor := func(name string, arg ...string) ([]byte, error) {
		if "/usr/bin/local/opk/policy-cmd" == name {
			return []byte("Thor Odin's son, protector of mankind"), nil
		}
		return nil, fmt.Errorf("command not found")
	}

	tests := []struct {
		name  string
		files map[string]string // File name to content mapping
	}{
		{
			name: "Valid plugin config",
			files: map[string]string{
				"valid_policy.yml": `
name: Example Policy Command
enforce_providers: true
command: /usr/bin/local/opk/policy-cmd %sub %iss %aud`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockFs := afero.NewMemMapFs()
			tempDir, _ := afero.TempDir(mockFs, "", "policy_test")

			// Write test config plugins files
			for fileName, content := range tt.files {
				err := afero.WriteFile(mockFs, filepath.Join(tempDir, fileName), []byte(content), 0644)
				require.NoError(t, err)
			}

			enforcer := &PolicyPluginEnforcer{
				Fs:          mockFs,
				cmdExecutor: mockCmdExecutor,
			}
			// TODO: Tokens
			tokens := map[string]string{
				"sub": "Thor",
				"iss": "",
				"aud": "",
			}
			res, err := enforcer.CheckPolicies(tempDir, tokens)
			require.NoError(t, err)
			require.Len(t, res, 1)
		})
	}

}
