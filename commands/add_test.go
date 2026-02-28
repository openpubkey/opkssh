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
	"os/user"
	"testing"

	"github.com/openpubkey/opkssh/policy"
	"github.com/openpubkey/opkssh/policy/files"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

// Duplicates code from multipolicyloader_test.go
type MockUserLookup struct {
	// User is returned on any call to Lookup() if Error is nil
	User *user.User
	// Error is returned on any call to Lookup() if non-nil
	Error error
}

// Lookup implements policy.UserLookup
func (m *MockUserLookup) Lookup(username string) (*user.User, error) {
	if m.Error == nil {
		return m.User, nil
	} else {
		return nil, m.Error
	}
}

var ValidUser *user.User = &user.User{HomeDir: "/home/foo", Username: "foo"}

func MockAddCmd(mockFs afero.Fs) *AddCmd {
	mockUserLookup := &MockUserLookup{User: ValidUser}

	mockHomePolicyLoader := &policy.HomePolicyLoader{
		PolicyLoader: &policy.PolicyLoader{
			FileLoader: files.FileLoader{
				Fs:           mockFs,
				RequiredPerm: files.ModeHomePerms,
			},
			UserLookup: mockUserLookup,
		},
	}

	mockSystemPolicyLoader := &policy.SystemPolicyLoader{
		PolicyLoader: &policy.PolicyLoader{
			FileLoader: files.FileLoader{
				Fs:           mockFs,
				RequiredPerm: files.ModeSystemPerms,
			},
			UserLookup: mockUserLookup,
		},
	}

	return &AddCmd{
		HomePolicyLoader:   mockHomePolicyLoader,
		SystemPolicyLoader: mockSystemPolicyLoader,
		Username:           ValidUser.Username,
	}

}

func TestAddErrors(t *testing.T) {
	principal := "foo"
	userEmail := "alice@example.com"
	issuer := "gitlab"

	// Test when the system policy file does not exist
	mockEmptyFs := afero.NewMemMapFs()
	addCmd := MockAddCmd(mockEmptyFs)
	policyPath, err := addCmd.Run(principal, userEmail, issuer)
	require.ErrorContains(t, err, "file does not exist")
	require.Empty(t, policyPath)

	// Create system policy file
	mockFs := afero.NewMemMapFs()
	_, err = mockFs.Create(policy.SystemDefaultPolicyPath)

	require.NoError(t, err)

	err = mockFs.Chmod(policy.SystemDefaultPolicyPath, 0640)
	require.NoError(t, err)

	addCmd = MockAddCmd(mockFs)
	policyPath, err = addCmd.Run(principal, userEmail, issuer)
	require.NoError(t, err)
	require.Equal(t, policy.SystemDefaultPolicyPath, policyPath)

	systemPolicyFile, err := mockFs.Open(policyPath)
	require.NoError(t, err)
	policyContent, err := afero.ReadAll(systemPolicyFile)
	require.NoError(t, err)
	expectedPolicyContent := principal + " " + userEmail + " " + issuer + "\n"
	require.Equal(t, expectedPolicyContent, string(policyContent))
}

func TestAddUniqueness(t *testing.T) {

	mockFs := afero.NewMemMapFs()
	_, err := mockFs.Create(policy.SystemDefaultPolicyPath)
	require.NoError(t, err)
	err = mockFs.Chmod(policy.SystemDefaultPolicyPath, 0640)
	require.NoError(t, err)
	addCmd := MockAddCmd(mockFs)

	policyPath, err := addCmd.Run("user1", "alice@example.com", "google")
	require.NoError(t, err)
	require.Equal(t, policy.SystemDefaultPolicyPath, policyPath)

	systemPolicyFile, err := mockFs.Open(policyPath)
	require.NoError(t, err)
	policyContent, err := afero.ReadAll(systemPolicyFile)
	require.NoError(t, err)
	require.Equal(t, "user1 alice@example.com google\n", string(policyContent)) // Should only have one entry

	policyPath, err = addCmd.Run("user1", "alice@example.com", "google")
	require.NoError(t, err)

	systemPolicyFile, err = mockFs.Open(policyPath)
	require.NoError(t, err)
	policyContent, err = afero.ReadAll(systemPolicyFile)
	require.NoError(t, err)
	require.Equal(t, "user1 alice@example.com google\n", string(policyContent)) // Should still have only one entry

	policyPath, err = addCmd.Run("user2", "alice@example.com", "google")
	require.NoError(t, err)

	systemPolicyFile, err = mockFs.Open(policyPath)
	require.NoError(t, err)
	policyContent, err = afero.ReadAll(systemPolicyFile)
	require.NoError(t, err)

	// Should have only two entries
	require.Equal(t, "user1 alice@example.com google\nuser2 alice@example.com google\n", string(policyContent))

	// Duplicate entry for user2 should be skipped
	policyPath, err = addCmd.Run("user2", "alice@example.com", "google")
	require.NoError(t, err)

	systemPolicyFile, err = mockFs.Open(policyPath)
	require.NoError(t, err)
	policyContent, err = afero.ReadAll(systemPolicyFile)
	require.NoError(t, err)

	// Should still have only two entries
	require.Equal(t, "user1 alice@example.com google\nuser2 alice@example.com google\n", string(policyContent))
}
