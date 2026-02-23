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
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/util"
	"github.com/openpubkey/opkssh/policy/files"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

type mockFile struct {
	Name       string
	Permission fs.FileMode
	Content    string
}

func TestLoadPolicyPluginsMissing(t *testing.T) {
	mockFs := afero.NewMemMapFs()
	enforcer := &PolicyPluginEnforcer{
		Fs: mockFs,
		permChecker: files.PermsChecker{
			Fs: mockFs,
			CmdRunner: func(name string, arg ...string) ([]byte, error) {
				return []byte("root" + " " + "group"), nil
			},
		},
	}

	// Load policy commands
	_, err := enforcer.loadPlugins("/should/not/exist")
	require.ErrorIs(t, err, os.ErrNotExist)
}

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
command: /usr/bin/local/opk/policy-cmd`,
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
command: /usr/bin/local/opk/policy-cmd
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
		iss, _ := os.LookupEnv("OPKSSH_PLUGIN_ISS")
		sub, _ := os.LookupEnv("OPKSSH_PLUGIN_SUB")
		aud, _ := os.LookupEnv("OPKSSH_PLUGIN_AUD")

		if name == "/usr/bin/local/opk/policy-cmd" {

			if len(arg) != 3 {
				return nil, fmt.Errorf("expected 3 arguments, got %d", len(arg))
			} else if iss == "https://example.com" && sub == "1234" && aud == "abcd" {
				return []byte("allow"), nil
			} else if iss == "https://example.com" && sub == "sub with spaces" && aud == "abcd" {
				return []byte("allow"), nil
			} else if iss == "https://example.com" && sub == "sub\"withquote" && aud == "abcd" {
				return []byte("allow"), nil
			} else {
				// Designed to test an command that doesn't output an error but returns deny. Deny should return an error as well.
				return []byte("deny"), nil
			}
		}
		return nil, fmt.Errorf("command '%s' not found", name)
	}

	validPluginConfigFile := []mockFile{
		{
			Name:       "valid_policy.yml",
			Permission: 0640,
			Content: `
name: Example Policy Command
enforce_providers: true
command: /usr/bin/local/opk/policy-cmd arg1 arg2 arg3`}}

	missingCommandConfig := []mockFile{
		{
			Name:       "missing-command.yml",
			Permission: 0640,
			Content: `
name: Example Policy Command
enforce_providers: true
command: /usr/bin/local/opk/missing-cmd`}}

	invalidCommandConfig := []mockFile{
		{
			Name:       "missing-command.yml",
			Permission: 0640,
			Content: `
name: Example Policy Command
enforce_providers: true
command: /usr/bin/local/opk/missing-cmd"`}}

	tests := []struct {
		name                string
		tokens              map[string]string
		files               []mockFile // File name to content mapping
		cmdExecutor         func(name string, arg ...string) ([]byte, error)
		expectedAllowed     bool
		expectedResultCount int
		expectErrorCount    int
		errorExpected       string
	}{
		{
			name: "Valid plugin config",
			tokens: map[string]string{
				"OPKSSH_PLUGIN_ISS": "https://example.com",
				"OPKSSH_PLUGIN_SUB": "1234",
				"OPKSSH_PLUGIN_AUD": "abcd",
			},
			files:               validPluginConfigFile,
			cmdExecutor:         mockCmdExecutor,
			expectedAllowed:     true,
			expectedResultCount: 1,
			expectErrorCount:    0,
		},
		{
			name: "Plugin config not found",
			tokens: map[string]string{
				"OPKSSH_PLUGIN_ISS": "https://example.com",
				"OPKSSH_PLUGIN_SUB": "1234",
				"OPKSSH_PLUGIN_AUD": "abcd",
			},
			files:               missingCommandConfig,
			cmdExecutor:         mockCmdExecutor,
			expectedAllowed:     false,
			expectedResultCount: 1,
			expectErrorCount:    1,
			errorExpected:       "file does not exist",
		},
		{
			name: "Check we handle spaces in claims",
			tokens: map[string]string{
				"OPKSSH_PLUGIN_ISS": "https://example.com",
				"OPKSSH_PLUGIN_SUB": "sub with spaces",
				"OPKSSH_PLUGIN_AUD": "abcd",
			},
			files:               validPluginConfigFile,
			cmdExecutor:         mockCmdExecutor,
			expectedAllowed:     true,
			expectedResultCount: 1,
			expectErrorCount:    0,
			errorExpected:       "",
		},
		{
			name: "Test we handle quotes in tokens",
			tokens: map[string]string{
				"OPKSSH_PLUGIN_ISS": "https://example.com",
				"OPKSSH_PLUGIN_SUB": `sub"withquote`,
				"OPKSSH_PLUGIN_AUD": "abcd",
			},
			files:               validPluginConfigFile,
			cmdExecutor:         mockCmdExecutor,
			expectedAllowed:     true,
			expectedResultCount: 1,
			expectErrorCount:    0,
			errorExpected:       "",
		},
		{
			name: "Policy command denial",
			tokens: map[string]string{
				"OPKSSH_PLUGIN_ISS": "https://example.com",
				"OPKSSH_PLUGIN_SUB": "wrong",
				"OPKSSH_PLUGIN_AUD": "abcd",
			},
			files:               validPluginConfigFile,
			cmdExecutor:         mockCmdExecutor,
			expectedAllowed:     false,
			expectedResultCount: 1,
			expectErrorCount:    0,
			errorExpected:       "",
		},
		{
			name: "Policy invalid command template",
			tokens: map[string]string{
				"OPKSSH_PLUGIN_ISS": "https://example.com",
				"OPKSSH_PLUGIN_SUB": "1234",
				"OPKSSH_PLUGIN_AUD": "abcd",
			},
			files:               invalidCommandConfig,
			cmdExecutor:         mockCmdExecutor,
			expectedAllowed:     false,
			expectedResultCount: 1,
			expectErrorCount:    1,
			errorExpected:       "Unterminated double-quoted string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Ensure we flush all OPKSSH_PLUGIN_ env vars before and after the test.
			for _, envVar := range os.Environ() {
				if strings.HasPrefix(envVar, "OPKSSH_PLUGIN_") {
					envVarName := strings.Split(envVar, "=")[0]
					_ = os.Unsetenv(envVarName)
					defer func(key string) {
						_ = os.Unsetenv(key)
					}(envVarName)
				}
			}

			mockFs := afero.NewMemMapFs()
			tempDir, _ := afero.TempDir(mockFs, "", "policy_test")

			// Write test config plugins files
			for _, configFile := range tt.files {
				err := afero.WriteFile(mockFs, filepath.Join(tempDir, configFile.Name), []byte(configFile.Content), configFile.Permission)
				require.NoError(t, err)
			}

			// Create the command we are going to call. It needs to be exist but it can be empty.
			err := afero.WriteFile(mockFs, filepath.Join("/usr/bin/local/opk/policy-cmd"), []byte(""), 0755)
			require.NoError(t, err)

			// We create this command with bad permissions and then trigger it from a config file that points to it
			err = afero.WriteFile(mockFs, filepath.Join("/usr/bin/local/opk/bad-perms-policy-cmd"), []byte(""), 0766)
			require.NoError(t, err)

			enforcer := &PolicyPluginEnforcer{
				Fs:          mockFs,
				cmdExecutor: tt.cmdExecutor,
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
			"Danger!!! Policy plugin command (%s) returned 'allow' but the plugin command did not approve. If you encounter this, report this as a vulnerability.",
			result.Path,
		),
		func() {
			_ = results.Allowed()
		},
	)
}

func TestPluginUnsetsEnvVar(t *testing.T) {
	mockFs := afero.NewMemMapFs()
	tempDir, _ := afero.TempDir(mockFs, "", "policy_test")

	enforcer := &PolicyPluginEnforcer{
		Fs: mockFs,
		cmdExecutor: func(name string, arg ...string) ([]byte, error) {
			_, okTestValue := os.LookupEnv("OPKSSH_PLUGIN_TESTVALUE")
			issValue, okIss := os.LookupEnv("OPKSSH_PLUGIN_ISS")
			require.False(t, okTestValue, "OPKSSH_PLUGIN_TESTVALUE should have been unset before calling the command")
			require.True(t, okIss, "OPKSSH_PLUGIN_ISS should still be set before calling the command")
			require.Equal(t, issValue, "https://example.com")
			return []byte("allow"), nil
		},
		permChecker: files.PermsChecker{
			Fs: mockFs,
			CmdRunner: func(name string, arg ...string) ([]byte, error) {
				return []byte("root" + " " + "group"), nil
			},
		},
	}

	// Write test config plugins files
	err := afero.WriteFile(mockFs, filepath.Join(tempDir, "policy.yml"), []byte(`
name: Example Policy Command
enforce_providers: true
command: /usr/bin/local/opk/policy-cmd arg1 arg2 arg3`), 0640)
	require.NoError(t, err)

	os.Setenv("OPKSSH_PLUGIN_TESTVALUE", "testvalue")
	os.Setenv("OPKSSH_PLUGIN_ISS", "should be overwritten")
	res, err := enforcer.checkPolicies(tempDir, map[string]string{"OPKSSH_PLUGIN_ISS": "https://example.com"})
	require.NoError(t, err)
	require.NotNil(t, res)
}

func TestPublicCheckPolicy(t *testing.T) {
	mockFs := afero.NewMemMapFs()
	tempDir, _ := afero.TempDir(mockFs, "", "policy_test")

	enforcer := &PolicyPluginEnforcer{
		Fs: mockFs,
		cmdExecutor: func(name string, arg ...string) ([]byte, error) {
			_, okTestValue := os.LookupEnv("OPKSSH_PLUGIN_TESTVALUE")
			_, okIss := os.LookupEnv("OPKSSH_PLUGIN_ISS")
			require.False(t, okTestValue, "OPKSSH_PLUGIN_TESTVALUE should have been unset before calling the command")
			require.True(t, okIss, "OPKSSH_PLUGIN_ISS should still be set before calling the command")
			return []byte("allow"), nil
		},
		permChecker: files.PermsChecker{
			Fs: mockFs,
			CmdRunner: func(name string, arg ...string) ([]byte, error) {
				return []byte("root" + " " + "group"), nil
			},
		},
	}

	// Write test config plugins files
	err := afero.WriteFile(mockFs, filepath.Join(tempDir, "policy.yml"), []byte(`
name: Example Policy Command
enforce_providers: true
command: /usr/bin/local/opk/policy-cmd arg1 arg2 arg3`), 0640)
	require.NoError(t, err)

	alg := jwa.ES256
	signer, err := util.GenKeyPair(alg)
	require.NoError(t, err)

	providerOpts := providers.DefaultMockProviderOpts()
	op, _, idtTemplate, err := providers.NewMockProvider(providerOpts)
	require.NoError(t, err)

	mockEmail := "arthur.aardvark@example.com"
	idtTemplate.ExtraClaims = map[string]any{
		"email": mockEmail,
	}

	client, err := client.New(op, client.WithSigner(signer, alg))
	require.NoError(t, err)

	pkt, err := client.Auth(context.Background())
	require.NoError(t, err)

	res, err := enforcer.CheckPolicies(tempDir, pkt, "", "root", "ssh-cert", "ssh-rsa", nil)
	require.NoError(t, err)
	require.NotNil(t, res)

	brokenPkt := pkt
	brokenPkt.OpToken = []byte("corrupt.corrupt.corrupt")

	res, err = enforcer.CheckPolicies(tempDir, brokenPkt, "", "root", "ssh-cert", "ssh-rsa", nil)
	require.Error(t, err)
	require.Nil(t, res)
}
