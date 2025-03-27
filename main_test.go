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
			wantErr:       errors.New("invalid OpenSSH version"),
		},
		{
			name:          "No OpenSSH prefix at all",
			input:         "Completely invalid input",
			wantIsGreater: false,
			wantErr:       errors.New("invalid OpenSSH version"),
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
			wantOutput: "OPKSSH (OpenPubkey SSH) CLI: command choices are: login, verify, and add",
			wantExit:   1,
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
			wantOutput: "ERROR! Unrecognized command: unknown",
			wantExit:   1,
		},
		{
			name:       "Add command with missing arguments",
			args:       []string{"opkssh", "add"},
			wantOutput: "Invalid number of arguments for add, expected: `<Principal> <Email> <Issuer>`",
			wantExit:   1,
		},
		{
			name:       "Login command with provider bad provider value",
			args:       []string{"opkssh", "login", "-provider=badvalue"},
			wantOutput: "ERROR Invalid provider argument format. Expected format <issuer>,<client_id> or <issuer>,<client_id>,<client_secret>",
			wantExit:   1,
		},
		{
			name:       "Login command with provider bad provider issuer value",
			args:       []string{"opkssh", "login", "-provider=badissuer.com,client_id"},
			wantOutput: "ERROR Invalid provider issuer value. Expected issuer to start with 'https://' got (badissuer.com)",
			wantExit:   1,
		},

		{
			name:       "Login command with provider bad provider good azure issuer but no client id value",
			args:       []string{"opkssh", "login", "-provider=https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0,"},
			wantOutput: "ERROR Invalid provider client-ID value got ()",
			wantExit:   1,
		},
		{
			name:       "Login command with provider bad provider good google issuer but no client id value",
			args:       []string{"opkssh", "login", "-provider=https://accounts.google.com,client_id"},
			wantOutput: "ERROR Invalid provider argument format. Expected format for google: <issuer>,<client_id>,<client_secret>",
			wantExit:   1,
		},
		{
			name:       "Login command with provider bad provider good google issuer but no client secret value",
			args:       []string{"opkssh", "login", "-provider=https://accounts.google.com,client_id,"},
			wantOutput: "ERROR Invalid provider client secret value got ()",
			wantExit:   1,
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
