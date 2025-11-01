// Copyright 2024 OpenPubkey
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

package main

import (
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsOpenSSHVersion8Dot1OrGreater(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		wantIsGreater bool
		wantErr       error
	}{
		{
			name:          "Exact 8.1",
			input:         "OpenSSH_8.1",
			wantIsGreater: true,
			wantErr:       nil,
		},
		{
			name:          "Above 8.1 (8.4)",
			input:         "OpenSSH_8.4",
			wantIsGreater: true,
			wantErr:       nil,
		},
		{
			name:          "Above 8.1 with patch (9.9p1)",
			input:         "OpenSSH_9.9p1",
			wantIsGreater: true,
			wantErr:       nil,
		},
		{
			name:          "Below 8.1 (7.9)",
			input:         "OpenSSH_7.9",
			wantIsGreater: false,
			wantErr:       nil,
		},
		{
			name:          "Multiple dotted version above 8.1 (8.1.2)",
			input:         "OpenSSH_8.1.2",
			wantIsGreater: true,
			wantErr:       nil,
		},
		{
			name:          "Multiple dotted version below 8.1 (7.10.3)",
			input:         "OpenSSH_7.10.3",
			wantIsGreater: false,
			wantErr:       nil,
		},
		{
			name:          "Malformed version string",
			input:         "OpenSSH_, something not right",
			wantIsGreater: false,
			wantErr:       errors.New("invalid OpenSSH version format: OpenSSH_"),
		},
		{
			name:          "No OpenSSH prefix at all",
			input:         "Completely invalid input",
			wantIsGreater: false,
			wantErr:       errors.New("invalid OpenSSH version format: Completely invalid input"),
		},
		{
			name:          "Includes trailing info (8.2, Raspbian-1)",
			input:         "OpenSSH_8.2, Raspbian-1",
			wantIsGreater: true,
			wantErr:       nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIsGreater, gotErr := isOpenSSHVersion8Dot1OrGreater(tt.input)

			if gotIsGreater != tt.wantIsGreater {
				t.Errorf(
					"isOpenSSHVersion8Dot1OrGreater(%q) got %v; want %v",
					tt.input,
					gotIsGreater,
					tt.wantIsGreater,
				)
			}

			if (gotErr != nil) != (tt.wantErr != nil) {
				t.Errorf(
					"isOpenSSHVersion8Dot1OrGreater(%q) error = %v; want %v",
					tt.input,
					gotErr,
					tt.wantErr,
				)
			} else if gotErr != nil && tt.wantErr != nil {
				if gotErr.Error() != tt.wantErr.Error() {
					t.Errorf("Unexpected error message. got %q; want %q",
						gotErr.Error(), tt.wantErr.Error())
				}
			}
		})
	}
}

func RunCliAndCaptureResult(t *testing.T, args []string) (string, int) {
	// Backup and defer restore of os.Args
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = args

	// Capture output
	oldStdout := os.Stdout
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stdout = w
	os.Stderr = w

	// Run the opkssh cli
	exitCode := run()

	// Restore stdout and stderr
	w.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	// Read captured output
	var cmdOutput strings.Builder
	_, err := io.Copy(&cmdOutput, r)
	require.NoError(t, err)

	return cmdOutput.String(), exitCode
}

func TestRun(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantOutput string
		wantExit   int
	}{
		{
			name:       "No arguments",
			args:       []string{"opkssh"},
			wantOutput: "SSH with OpenPubkey",
			wantExit:   0,
		},
		{
			name:       "Root Help flag",
			args:       []string{"opkssh", "--help"},
			wantOutput: "opkssh [command]",
			wantExit:   0,
		},
		{
			name:       "Add Help flag",
			args:       []string{"opkssh", "add", "--help"},
			wantOutput: "Add appends a new policy entry in the auth_id policy file",
			wantExit:   0,
		},
		{
			name:       "Login Help flag",
			args:       []string{"opkssh", "login", "--help"},
			wantOutput: "Login creates opkssh SSH keys",
			wantExit:   0,
		},
		{
			name:       "Verify Help flag",
			args:       []string{"opkssh", "verify", "--help"},
			wantOutput: "Verify extracts a PK token",
			wantExit:   0,
		},
		{
			name:       "Version flag",
			args:       []string{"opkssh", "--version"},
			wantOutput: "unversioned",
			wantExit:   0,
		},
		{
			name:       "Unrecognized command",
			args:       []string{"opkssh", "unknown"},
			wantOutput: "Error: unknown command \"unknown\"",
			wantExit:   1,
		},
		{
			name:       "Add command with missing arguments",
			args:       []string{"opkssh", "add"},
			wantOutput: "Error: accepts 3 arg(s), received 0",
			wantExit:   1,
		},
		{
			name:       "Login command with bad arguments",
			args:       []string{"opkssh", "login", "-badarg"},
			wantOutput: "Error: unknown shorthand flag:",
			wantExit:   1,
		},
		{
			name:       "Login command with missing providers arguments",
			args:       []string{"opkssh", "login", "--provider"},
			wantOutput: "Error: flag needs an argument: --provider",
			wantExit:   1,
		},
		{
			name:       "Login command with provider bad provider value",
			args:       []string{"opkssh", "login", "--provider=badvalue"},
			wantOutput: "error parsing provider argument: invalid provider config string. Expected format <issuer>,<client_id> or <issuer>,<client_id>,<client_secret> or <issuer>,<client_id>,<client_secret>,<scopes>",
			wantExit:   1,
		},
		{
			name:       "Login command with provider bad provider issuer value",
			args:       []string{"opkssh", "login", "--provider=badissuer.com,client_id"},
			wantOutput: "error creating provider from config: invalid provider issuer value. Expected issuer to start with 'https://' got (badissuer.com)",
			wantExit:   1,
		},
		{
			name:       "Login command with provider bad provider good azure issuer but no client id value",
			args:       []string{"opkssh", "login", "--provider=https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0,"},
			wantOutput: "error parsing provider argument: invalid provider client-ID value got ()",
			wantExit:   1,
		},
		{
			name:       "Login command with provider bad provider good google issuer but no client id value",
			args:       []string{"opkssh", "login", "--provider=https://accounts.google.com,client_id"},
			wantOutput: "error parsing provider argument: invalid provider argument format. Expected format for google: <issuer>,<client_id>,<client_secret>",
			wantExit:   1,
		},
		{
			name:       "Login command with provider bad provider good google issuer but no client secret value",
			args:       []string{"opkssh", "login", "--provider=https://accounts.google.com,client_id,"},
			wantOutput: "error parsing provider argument: invalid provider argument format. Expected format for google: <issuer>,<client_id>,<client_secret>",
			wantExit:   1,
		},
		{
			name:       "Login command with alias bad alias",
			args:       []string{"opkssh", "login", "badalias"},
			wantOutput: "error getting provider config for alias badalias",
			wantExit:   1,
		},
		{
			name:       "Verify command fail on bad log file path",
			args:       []string{"opkssh", "verify", "arg1", "arg2", "arg3"},
			wantOutput: "Error opening log file:",
			wantExit:   1,
		},
		{
			name: "Client provider list",
			args: []string{"opkssh", "client", "provider", "list", "--config-path=commands/config/default-client-config.yml"},
			wantOutput: "" +
				"google    https://accounts.google.com\n" +
				"azure     https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0\n" +
				"microsoft https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0\n" +
				"gitlab    https://gitlab.com\n" +
				"hello     https://issuer.hello.coop\n",
			wantExit: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmdOutput, exitCode := RunCliAndCaptureResult(t, tt.args)
			require.Contains(t, cmdOutput, tt.wantOutput, "Incorrect command output")
			require.Equal(t, tt.wantExit, exitCode, "Incorrect Exit code")

		})
	}
}

func TestWithEnvVars(t *testing.T) {
	tests := []struct {
		name       string
		envVar     string
		envValue   string
		args       []string
		wantOutput string
		wantExit   int
	}{
		{
			name:       "Set OPKSSH_DEFAULT to bad value",
			envVar:     "OPKSSH_DEFAULT",
			envValue:   "badvalue",
			args:       []string{"opkssh", "login", "--config-path", "/foo/bar"},
			wantOutput: "error getting provider config for alias badvalue",
			wantExit:   1,
		},
		{
			name:       "Set OPKSSH_PROVIDERS to bad value",
			envVar:     "OPKSSH_PROVIDERS",
			envValue:   "badvalue",
			args:       []string{"opkssh", "login", "--config-path", "/foo/bar"},
			wantOutput: "Expected format <alias>,<issuer>,<client_id> or <alias>,<issuer>,<client_id>,<client_secret> or <alias>,<issuer>,<client_id>,<client_secret>,<scopes>",
			wantExit:   1,
		},
		{
			name:       "Set OPKSSH_PROVIDERS with duplicates aliases",
			envVar:     "OPKSSH_PROVIDERS",
			envValue:   "alias1,https://accounts.google.com,client_id,client_secret,scope1;alias1,https://accounts.google.com,client_id,client_secret,scope2",
			args:       []string{"opkssh", "login", "--config-path", "/foo/bar"},
			wantOutput: "provider in web chooser found with duplicate issuer",
			wantExit:   1,
		},
		{
			name:       "Set OPKSSH_PROVIDERS with bad provider",
			envVar:     "OPKSSH_PROVIDERS",
			envValue:   "google,http://insecure.badprovider.com,client_id,client_secret,openid profile",
			args:       []string{"opkssh", "login", "--config-path", "/foo/bar"},
			wantOutput: "error creating provider from config: invalid provider issuer value. Expected issuer to start with 'https://' got (http://insecure.badprovider.com)",
			wantExit:   1,
		},
		{
			name:       "Set OPKSSH_PROVIDERS with good provider but asking for wrong alias",
			envVar:     "OPKSSH_PROVIDERS",
			envValue:   "goodprovider,https://goodprovider.com,client_id,client_secret,openid profile",
			args:       []string{"opkssh", "login", "badalias", "--config-path", "/foo/bar"},
			wantOutput: "error getting provider config for alias badalias",
			wantExit:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = os.Setenv(tt.envVar, tt.envValue)
			defer func(key string) {
				_ = os.Unsetenv(key)
			}(tt.envVar)

			cmdOutput, exitCode := RunCliAndCaptureResult(t, tt.args)
			require.Contains(t, cmdOutput, tt.wantOutput, "Incorrect command output")
			require.Equal(t, tt.wantExit, exitCode, "Incorrect Exit code")
		})
	}
}
