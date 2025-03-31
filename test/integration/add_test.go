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

//go:build integration

package integration

import (
	"fmt"
	"io"
	"path"
	"strings"
	"testing"

	"github.com/openpubkey/opkssh/policy"
	"github.com/openpubkey/opkssh/policy/files"
	"github.com/openpubkey/opkssh/test/integration/ssh_server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
)

const SudoerUser string = "test"
const UnprivUser string = "test2"
const RootUser string = "root"
const UserGroup string = "opksshuser"

func executeCommandAsUser(t *testing.T, container testcontainers.Container, cmd []string, user string) (int, string) {
	// Execute command
	execOpts := []tcexec.ProcessOption{tcexec.Multiplexed(), tcexec.WithUser(user)}
	code, reader, err := container.Exec(TestCtx, cmd, execOpts...)
	require.NoError(t, err)

	// Read stdout/stderr from command execution
	b, err := io.ReadAll(reader)
	require.NoError(t, err)
	t.Logf("Command `%s` being run as user %s returned exit code %d and the following stdout/stderr:\n%s", strings.Join(cmd, " "), user, code, string(b))

	return code, string(b)
}

func FileExists(t *testing.T, container testcontainers.Container, filePath string) bool {
	code, _ := executeCommandAsUser(t, container, []string{"test", "-f", filePath}, RootUser)
	if code != 0 {
		return false
	}
	return true
}

func CreateAuthIdFile(t *testing.T, container testcontainers.Container, filePath string, cmdUser string, userPolicyFile bool) {
	// Create the auth_id file if it doesn't exist
	code, _ := executeCommandAsUser(t, container, []string{"mkdir", "-p", path.Dir(filePath)}, RootUser)
	require.Equal(t, 0, code, "failed to create user auth_id directory")
	code, _ = executeCommandAsUser(t, container, []string{"touch", filePath}, RootUser)
	require.Equal(t, 0, code, "failed to create user auth_id file")
	if userPolicyFile {
		// Set the permissions for the user policy file to 600
		code, _ = executeCommandAsUser(t, container, []string{"chmod", "600", filePath}, RootUser)
		require.Equal(t, 0, code, "failed to set permissions for user policy file")
		userAndGroup := fmt.Sprintf("%s:%s", cmdUser, cmdUser)
		code, _ = executeCommandAsUser(t, container, []string{"chown", userAndGroup, filePath}, RootUser)
		require.Equal(t, 0, code, "failed to set ownership for user policy file")
	} else {
		// Set the permissions for the system policy file to 640
		code, _ = executeCommandAsUser(t, container, []string{"chmod", "640", filePath}, RootUser)
		require.Equal(t, 0, code, "failed to set permissions for system policy file")
		code, _ = executeCommandAsUser(t, container, []string{"chown", "root:opksshuser", filePath}, RootUser)
		require.Equal(t, 0, code, "failed to set ownership for system policy file")
	}
}

func TestAdd(t *testing.T) {
	// Test adding an allowed principal to an opkssh policy
	issuer := fmt.Sprintf("http://oidc.local:%s/", issuerPort)

	tests := []struct {
		name                      string
		binaryPath                string
		useSudo                   bool
		cmdUser                   string
		desiredPrincipal          string
		preexistingHomeAuthIdFile bool
		shouldCmdFail             bool
	}{
		{
			name:                      "sudoer user can update root policy",
			binaryPath:                "/usr/local/bin/opkssh",
			useSudo:                   true,
			cmdUser:                   SudoerUser,
			desiredPrincipal:          SudoerUser,
			preexistingHomeAuthIdFile: true,
			shouldCmdFail:             false,
		},
		{
			name:                      "sudoer user can update root policy with principal != self",
			binaryPath:                "/usr/local/bin/opkssh",
			useSudo:                   true,
			cmdUser:                   SudoerUser,
			desiredPrincipal:          UnprivUser,
			preexistingHomeAuthIdFile: true,
			shouldCmdFail:             false,
		},
		{
			name:                      "unprivileged user creates an auth_id file (no preexisting ~/.opk/auth_id file)",
			binaryPath:                "/usr/local/bin/opkssh",
			useSudo:                   false,
			cmdUser:                   UnprivUser,
			desiredPrincipal:          UnprivUser,
			preexistingHomeAuthIdFile: false,
			shouldCmdFail:             false,
		},
		{
			name:                      "unprivileged user can update their user policy",
			binaryPath:                "/usr/local/bin/opkssh",
			useSudo:                   false,
			cmdUser:                   UnprivUser,
			desiredPrincipal:          UnprivUser,
			preexistingHomeAuthIdFile: true,
			shouldCmdFail:             false,
		},
		{
			name:                      "unprivileged user cannot add principal != self",
			binaryPath:                "/usr/local/bin/opkssh",
			useSudo:                   false,
			cmdUser:                   UnprivUser,
			desiredPrincipal:          SudoerUser,
			preexistingHomeAuthIdFile: true,
			shouldCmdFail:             true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test container (fresh container for each sub-test)
			container, err := ssh_server.RunOpkSshContainer(
				TestCtx,
				// This test is only using add, so we don't need to set these
				// arguments
				"",
				"",
				"",
				false, // Skip init policy as this test is testing "add" directly
			)
			require.NoError(t, err)
			t.Cleanup(func() {
				require.NoError(t, container.Terminate(TestCtx), "failed to terminate add_test container")
			})

			// Determine expected values based on sub-test options
			var expectedPolicyFilepath, expectedUser, expectedGroup, expectedPerms string
			var isUserPolicyFile bool
			if tt.useSudo {
				expectedPolicyFilepath = policy.SystemDefaultPolicyPath
				expectedUser = RootUser
				expectedGroup = UserGroup
				expectedPerms = "640"
				isUserPolicyFile = false
			} else {
				expectedPolicyFilepath = path.Join("/home/", tt.cmdUser, ".opk", "auth_id")
				expectedUser = tt.cmdUser
				expectedGroup = tt.cmdUser
				expectedPerms = "600"
				isUserPolicyFile = true
			}

			// Install automatically creates the system auth_id file, so can assume it exists
			if isUserPolicyFile {
				policyFileExists := FileExists(t, container.Container, expectedPolicyFilepath)
				require.False(t, policyFileExists, "home policy file should not exist yet in a fresh test container")

				// If test needs a preexisting auth_id file, create it
				if tt.preexistingHomeAuthIdFile {
					CreateAuthIdFile(t, container.Container, expectedPolicyFilepath, tt.cmdUser, isUserPolicyFile)
					policyFileExists := FileExists(t, container.Container, expectedPolicyFilepath)
					require.True(t, policyFileExists, "policy file should have been created in test container (test is broken)")
				}
			}

			// Build add command based on sub-test options
			addCmd := fmt.Sprintf("add %s foo@example.com %s", tt.desiredPrincipal, issuer)
			cmd := []string{tt.binaryPath, addCmd}
			if tt.useSudo {
				cmd = append([]string{"sudo"}, cmd...)
			}

			// Execute add command
			code, _ := executeCommandAsUser(t, container.Container, []string{"/bin/bash", "-c", strings.Join(cmd, " ")}, tt.cmdUser)

			if tt.shouldCmdFail {
				assert.Equal(t, 1, code, "add command should fail")
				if tt.preexistingHomeAuthIdFile && isUserPolicyFile {
					code, policyContents := executeCommandAsUser(t, container.Container, []string{"cat", expectedPolicyFilepath}, RootUser)
					require.Equal(t, 0, code, "failed to read policy file")
					assert.Empty(t, policyContents, "policy file should not be updated")
				} else {
					code, _ = executeCommandAsUser(t, container.Container, []string{"test", "-f", expectedPolicyFilepath}, RootUser)
					assert.NotEqual(t, 0, code, "policy file should not exist")
				}
			} else {
				require.Equal(t, 0, code, "failed to run add command")

				// Assert that the correct policy file is updated
				code, policyContents := executeCommandAsUser(t, container.Container, []string{"cat", expectedPolicyFilepath}, RootUser)
				require.Equal(t, 0, code, "failed to read policy file")
				gotPolicy := policy.FromTable([]byte(policyContents), "test-path")
				require.True(t, files.ConfigProblems().NoProblems())

				expectedPolicy := &policy.Policy{
					Users: []policy.User{
						{
							EmailOrSub: "foo@example.com",
							Principals: []string{tt.desiredPrincipal},
							Issuer:     issuer,
						},
					},
				}
				require.Equal(t, expectedPolicy, gotPolicy)
				// Assert that owner and permissions are still correct
				code, statOutput := executeCommandAsUser(t, container.Container, []string{"stat", "-c", "%U %G %a", expectedPolicyFilepath}, RootUser)
				require.Equal(t, 0, code, "failed to run stat command")
				statOutputSplit := strings.Split(strings.TrimSpace(statOutput), " ")
				require.Len(t, statOutputSplit, 3, "expected stat command to return 3 values")
				require.Equal(t, expectedUser, statOutputSplit[0])  // Assert user
				require.Equal(t, expectedGroup, statOutputSplit[1]) // Assert group
				require.Equal(t, expectedPerms, statOutputSplit[2]) // Assert permissions
			}

			// No matter what, if command fails or succeeds, the root policy
			// file should *never* be updated if the command was run without
			// sudo/as unprivileged user
			if !tt.useSudo {
				code, policyContents := executeCommandAsUser(t, container.Container, []string{"cat", policy.SystemDefaultPolicyPath}, RootUser)
				require.Equal(t, 0, code, "failed to read policy file")
				require.Empty(t, policyContents, "system policy file should not be updated if command was run without sudo")
			}
		})
	}
}
