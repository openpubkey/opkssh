//go:build !windows
// +build !windows

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

func TestEnumerateUserHomeDirs_Unix(t *testing.T) {
	t.Parallel()

	vfs := afero.NewMemMapFs()
	passwdContent := "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/sh\n"
	require.NoError(t, afero.WriteFile(vfs, "/etc/passwd", []byte(passwdContent), 0o644))

	cmd := &AuditCmd{
		Fs:  files.NewFileSystem(vfs, files.WithCmdRunner(func(string, ...string) ([]byte, error) { return nil, nil })),
		Out: &bytes.Buffer{},
	}

	entries, err := cmd.enumerateUserHomeDirs()
	require.NoError(t, err)
	require.Len(t, entries, 2)
	require.Equal(t, "root", entries[0].Username)
	require.Equal(t, "/root", entries[0].HomeDir)
	require.Equal(t, "alice", entries[1].Username)
	require.Equal(t, "/home/alice", entries[1].HomeDir)
}

func TestEnumerateUserHomeDirs_Unix_MissingPasswd(t *testing.T) {
	t.Parallel()

	vfs := afero.NewMemMapFs()

	cmd := &AuditCmd{
		Fs:  files.NewFileSystem(vfs, files.WithCmdRunner(func(string, ...string) ([]byte, error) { return nil, nil })),
		Out: &bytes.Buffer{},
	}

	_, err := cmd.enumerateUserHomeDirs()
	require.Error(t, err)
	require.Contains(t, err.Error(), "/etc/passwd not found")
}
