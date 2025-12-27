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

//go:build linux || darwin

package commands

import (
	"os/user"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

func TestReadHomeCmd(t *testing.T) {
	t.Parallel()

	homePolicyPath := "/home/alice/.opk/fake-path/1234_auth_id"
	validUser := &user.User{HomeDir: "/home/foo", Username: "foo"}

	// Test before we have setup the mocks, should error
	readHomeCmd := NewReadHomeCmd()
	policyFile, err := readHomeCmd.ReadHome(validUser.Username, homePolicyPath)

	require.Error(t, err, "expected error for nonexistent user")
	require.Nil(t, policyFile, "expected nil policyFile for nonexistent user")

	// Setup the mocks
	mockFs := afero.NewMemMapFs()
	readHomeCmd.Fs = mockFs
	readHomeCmd.UserLookup = &MockUserLookup{User: validUser}

	err = afero.WriteFile(mockFs, homePolicyPath, []byte("123456"), 0600)
	require.NoError(t, err, "failed to write mock home policy file")

	defaultHomePolicyPath := filepath.Join(validUser.HomeDir, ".opk", "auth_id")
	err = afero.WriteFile(mockFs, defaultHomePolicyPath, []byte("ABCDEF"), 0600)
	require.NoError(t, err, "failed to write mock default home policy file")

	policyFile, err = readHomeCmd.ReadHome(validUser.Username, "")
	require.NoError(t, err, "expected no error for valid user and existing file")
	require.NotNil(t, policyFile, "expected non-nil policyFile for valid user and existing file")
	require.Equal(t, []byte("ABCDEF"), policyFile, "unexpected policy file contents (default path)")

	policyFile, err = readHomeCmd.ReadHome(validUser.Username, homePolicyPath)
	require.NoError(t, err, "expected no error for valid user and existing file")
	require.NotNil(t, policyFile, "expected non-nil policyFile for valid user and existing file")
	require.Equal(t, []byte("123456"), policyFile, "unexpected policy file contents (path overridden)")
}
