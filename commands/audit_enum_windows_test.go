//go:build windows
// +build windows

// Copyright 2026 OpenPubkey
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
	"testing"

	"github.com/openpubkey/opkssh/policy/files"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

func TestEnumerateUserHomeDirs_Windows(t *testing.T) {
	t.Parallel()

	vfs := afero.NewMemMapFs()
	cmd := &AuditCmd{
		Fs:         vfs,
		FileSystem: files.NewFileSystem(vfs),
		Out:        &bytes.Buffer{},
	}

	entries, err := cmd.enumerateUserHomeDirs()
	require.NoError(t, err)
	// On a running Windows machine there should be at least one user profile
	require.NotEmpty(t, entries, "expected at least one user profile from Windows registry")

	for _, e := range entries {
		require.NotEmpty(t, e.Username, "username should not be empty")
		require.NotEmpty(t, e.HomeDir, "home directory should not be empty")
	}
}
