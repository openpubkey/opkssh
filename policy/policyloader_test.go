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

package policy_test

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/openpubkey/opkssh/policy"
	"github.com/openpubkey/opkssh/policy/files"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

type MockUserLookup struct {
	// User is returned on any call to Lookup() if Error is nil
	User *user.User
	// Error is returned on any call to Lookup() if non-nil
	Error error
}

var _ policy.UserLookup = &MockUserLookup{}

// Lookup implements policy.UserLookup
func (m *MockUserLookup) Lookup(username string) (*user.User, error) {
	if m.Error == nil {
		return m.User, nil
	} else {
		return nil, m.Error
	}
}

// MockFsOpenError embeds an afero.MemMapFs (implements afero.Fs) but allows for
// finer control on when an error should be returned on a specific filepath
type MockFsOpenError struct {
	afero.MemMapFs

	fileToErrorMap map[string]error
}

func NewMockFsOpenError() *MockFsOpenError {
	return &MockFsOpenError{fileToErrorMap: make(map[string]error)}
}

func (m *MockFsOpenError) Open(name string) (afero.File, error) {
	err, ok := m.fileToErrorMap[name]
	if ok {
		return nil, err
	}
	return m.MemMapFs.Open(name)
}

// ErrorOn makes Open(fileName) return err
func (m *MockFsOpenError) ErrorOn(fileName string, err error) {
	m.fileToErrorMap[fileName] = err
}

func NewTestHomePolicyLoader(fs afero.Fs, userLookup policy.UserLookup) *policy.HomePolicyLoader {
	return &policy.HomePolicyLoader{
		PolicyLoader: &policy.PolicyLoader{
			FileLoader: files.FileLoader{
				Fs:           fs,
				RequiredPerm: files.ModeHomePerms,
			},
			UserLookup: userLookup,
		},
	}
}

func NewTestSystemPolicyLoader(fs afero.Fs, userLookup policy.UserLookup) *policy.SystemPolicyLoader {
	return &policy.SystemPolicyLoader{
		&policy.PolicyLoader{
			FileLoader: files.FileLoader{
				Fs:           fs,
				RequiredPerm: files.ModeSystemPerms,
			},
			UserLookup: userLookup,
		},
	}
}

var ValidUser *user.User = &user.User{HomeDir: "/home/foo", Username: "foo"}

func TestLoadUserPolicy_FailUserLookup(t *testing.T) {
	// Test that LoadUserPolicy returns an error when user lookup fails
	t.Parallel()

	fakeError := errors.New("fake error")
	mockUserLookup := &MockUserLookup{Error: fakeError}

	policyLoader := NewTestHomePolicyLoader(afero.NewMemMapFs(), mockUserLookup)
	policy, path, err := policyLoader.LoadHomePolicy("", false)

	require.ErrorIs(t, err, fakeError)
	require.Nil(t, policy, "should not return policy if error")
	require.Empty(t, path, "should not return path if error")
}

func TestLoadUserPolicy_NoUserHomeDir(t *testing.T) {
	// Test that LoadUserPolicy returns an error when the user does not have a
	// home directory
	t.Parallel()

	mockUserLookup := &MockUserLookup{User: &user.User{}}

	policyLoader := NewTestHomePolicyLoader(afero.NewMemMapFs(), mockUserLookup)
	policy, path, err := policyLoader.LoadHomePolicy("", false)

	require.Error(t, err, "should not read policy if user does not have a home directory")
	require.Nil(t, policy, "should not return policy if error")
	require.Empty(t, path, "should not return path if error")
}

func TestLoadUserPolicy_ErrorFile(t *testing.T) {
	// Test that LoadUserPolicy returns an error when the file is invalid
	t.Parallel()

	mockUserLookup := &MockUserLookup{User: ValidUser}
	policyLoader := NewTestHomePolicyLoader(afero.NewMemMapFs(), mockUserLookup)
	mockFs := policyLoader.FileLoader.Fs
	// Create policy file at user policy path with invalid data
	err := afero.WriteFile(mockFs, filepath.Join(ValidUser.HomeDir, ".opk", "auth_id"), []byte("{"), 0600)
	require.NoError(t, err)

	policy, path, err := policyLoader.LoadHomePolicy(ValidUser.Username, false)
	require.NoError(t, err)
	require.False(t, files.ConfigProblems().NoProblems())
	files.ConfigProblems().Clear()

	require.NotNil(t, policy, "should return policy even if error")
	require.NotEmpty(t, path, "should return path even if error")
}

func TestLoadUserPolicy_Success(t *testing.T) {
	// Test that LoadUserPolicy returns the policy when there are no errors
	t.Parallel()

	mockUserLookup := &MockUserLookup{User: ValidUser}
	policyLoader := NewTestHomePolicyLoader(afero.NewMemMapFs(), mockUserLookup)
	mockFs := policyLoader.FileLoader.Fs
	// Create policy file at path with valid file
	testPolicy := &policy.Policy{
		Users: []policy.User{
			{
				IdentityAttribute: "alice@example.com",
				Principals:        []string{"test"},
				Issuer:            "https://example.com",
			},
		},
	}
	testPolicyFile, err := testPolicy.ToTable()
	require.NoError(t, err)
	expectedPath := filepath.Join(ValidUser.HomeDir, ".opk", "auth_id")
	err = afero.WriteFile(mockFs, expectedPath, testPolicyFile, 0600)
	require.NoError(t, err)

	gotPolicy, gotPath, err := policyLoader.LoadHomePolicy(ValidUser.Username, false)

	require.NoError(t, err)
	require.Equal(t, testPolicy, gotPolicy)
	require.Equal(t, expectedPath, gotPath)
}

func TestLoadUserPolicy_Success_SkipInvalidEntries(t *testing.T) {
	// Test that LoadUserPolicy returns the policy when there are no errors and
	// correctly skips invalid entries
	t.Parallel()

	mockUserLookup := &MockUserLookup{User: ValidUser}
	policyLoader := NewTestHomePolicyLoader(afero.NewMemMapFs(), mockUserLookup)
	mockFs := policyLoader.FileLoader.Fs
	// Create policy file at path with valid file
	testPolicy := &policy.Policy{
		Users: []policy.User{
			{
				IdentityAttribute: "alice@example.com",
				Principals:        []string{"test"},
				Issuer:            "https://example.com",
			},
			{
				IdentityAttribute: "bob@example.com",
				Principals:        []string{"test"},
				Issuer:            "https://example.com",
			},
			{
				IdentityAttribute: "charlie@example.com",
				Principals:        []string{ValidUser.Username},
				Issuer:            "https://example.com",
			},
			{
				IdentityAttribute: "daniel@example.com",
				Principals:        []string{ValidUser.Username, "test", "test2"},
				Issuer:            "https://example.com",
			},
		},
	}
	// Expect only user statements that contain ValidUser.Username
	expectedPolicy := &policy.Policy{
		Users: []policy.User{
			{
				IdentityAttribute: "charlie@example.com",
				Principals:        []string{ValidUser.Username},
				Issuer:            "https://example.com",
			},
			{
				IdentityAttribute: "daniel@example.com",
				Principals:        []string{ValidUser.Username},
				Issuer:            "https://example.com",
			},
		},
	}
	testPolicyFile, err := testPolicy.ToTable()
	require.NoError(t, err)
	expectedPath := filepath.Join(ValidUser.HomeDir, ".opk", "auth_id")
	err = afero.WriteFile(mockFs, expectedPath, testPolicyFile, 0600)
	require.NoError(t, err)
	gotPolicy, gotPath, err := policyLoader.LoadHomePolicy(ValidUser.Username, true)

	require.NoError(t, err)
	require.Equal(t, expectedPolicy, gotPolicy)
	require.Equal(t, expectedPath, gotPath)
}

func TestLoadPolicyAtPath_FileMissing(t *testing.T) {
	// Test that LoadPolicyAtPath returns an error when the file cannot be
	// found at the specified path
	t.Parallel()

	mockUserLookup := &MockUserLookup{User: ValidUser}

	policyLoader := NewTestHomePolicyLoader(afero.NewMemMapFs(), mockUserLookup)
	contents, err := policyLoader.LoadPolicyAtPath("/auth_id")

	require.ErrorIs(t, err, os.ErrNotExist)
	require.Nil(t, contents, "should not return contents if error")
}

func TestLoadPolicyAtPath_ReadError(t *testing.T) {
	// Test that LoadPolicyAtPath returns an error when we fail to read the file
	// (but it exists)
	t.Parallel()

	mockUserLookup := &MockUserLookup{User: ValidUser}
	mockFs := NewMockFsOpenError()
	policyLoader := NewTestSystemPolicyLoader(
		mockFs,
		mockUserLookup,
	)
	// Create empty policy file with correct permissions
	err := afero.WriteFile(mockFs, policy.SystemDefaultPolicyPath, []byte{}, 0640)
	require.NoError(t, err)
	// Now make it so mock filesystem returns error when reading the file (must
	// do this after creating the SystemDefaultPolicyPath file above)
	fakeError := errors.New("fake error")
	mockFs.ErrorOn(policy.SystemDefaultPolicyPath, fakeError)

	contents, err := policyLoader.LoadPolicyAtPath(policy.SystemDefaultPolicyPath)

	require.ErrorIs(t, err, fakeError)
	require.Nil(t, contents, "should not return contents if error")
}

func TestLoadSystemDefaultPolicy_ErrorFile(t *testing.T) {
	// Test that LoadSystemDefaultPolicy returns an error when the file is
	// invalid
	t.Parallel()

	mockUserLookup := &MockUserLookup{User: ValidUser}
	policyLoader := NewTestSystemPolicyLoader(afero.NewMemMapFs(), mockUserLookup)
	mockFs := policyLoader.FileLoader.Fs
	// Create policy file at default path with invalid file
	err := afero.WriteFile(mockFs, policy.SystemDefaultPolicyPath, []byte("{"), 0640)
	require.NoError(t, err)
	policy, _, err := policyLoader.LoadSystemPolicy()
	require.NoError(t, err)
	require.False(t, files.ConfigProblems().NoProblems())
	files.ConfigProblems().Clear()

	require.NotNil(t, policy, "should return policy even if problems encountered")
}

func TestLoadSystemDefaultPolicy_Success(t *testing.T) {
	// Test that LoadSystemDefaultPolicy returns the policy when there are no
	// errors
	t.Parallel()

	mockUserLookup := &MockUserLookup{User: ValidUser}
	policyLoader := NewTestSystemPolicyLoader(afero.NewMemMapFs(), mockUserLookup)
	mockFs := policyLoader.FileLoader.Fs
	// Create policy file at default path with valid file
	testPolicy := &policy.Policy{
		Users: []policy.User{
			{
				IdentityAttribute: "alice@example.com",
				Principals:        []string{"test"},
				Issuer:            "https://example.com",
			},
		},
	}
	testPolicyFile, err := testPolicy.ToTable()
	require.NoError(t, err)
	err = afero.WriteFile(mockFs, policy.SystemDefaultPolicyPath, testPolicyFile, 0640)
	require.NoError(t, err)
	gotPolicy, _, err := policyLoader.LoadSystemPolicy()

	require.NoError(t, err)
	require.Equal(t, testPolicy, gotPolicy)
}

func TestDump_Success(t *testing.T) {
	// Test that Dump writes the policy to the mock filesystem when there are no
	// errors
	t.Parallel()

	mockUserLookup := &MockUserLookup{User: ValidUser}
	testPolicy := &policy.Policy{
		Users: []policy.User{
			{
				IdentityAttribute: "alice@example.com",
				Principals:        []string{"test"},
				Issuer:            "https://example.com",
			},
		},
	}
	expectedContents, err := testPolicy.ToTable()
	require.NoError(t, err)
	policyLoader := NewTestSystemPolicyLoader(afero.NewMemMapFs(), mockUserLookup)
	mockFs := policyLoader.FileLoader.Fs

	err = policyLoader.Dump(testPolicy, policy.SystemDefaultPolicyPath)

	require.NoError(t, err)
	gotContents, err := afero.ReadFile(mockFs, policy.SystemDefaultPolicyPath)
	require.NoError(t, err)
	require.Equal(t, expectedContents, gotContents)
}
