//go:build !windows
// +build !windows

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
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openpubkey/opkssh/policy/files"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

// TestEnvFromConfig_UnixPermissions tests Unix-specific permission checking
func TestEnvFromConfig_UnixPermissions(t *testing.T) {
	configContent := `---
env_vars:
  OPKSSH_TEST_EXAMPLE_VAR1: ABC
  OPKSSH_TEST_EXAMPLE_VAR2: DEF
`

	tests := []struct {
		name        string
		configFile  map[string]string
		permission  fs.FileMode
		Content     string
		owner       string
		group       string
		errorString string
	}{
		{
			name:        "Wrong Permissions",
			configFile:  map[string]string{"server_config.yml": configContent},
			permission:  0677,
			owner:       "root",
			group:       "opksshuser",
			errorString: "expected one of the following permissions [640], got (677)",
		},
		{
			name:        "Wrong ownership",
			configFile:  map[string]string{"server_config.yml": configContent},
			permission:  0640,
			owner:       "opksshuser",
			group:       "opksshuser",
			errorString: "expected owner (root), got (opksshuser)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Unset the environment variables after the test is done to avoid side effects
			defer func() {
				for _, v := range os.Environ() {
					if strings.HasPrefix(v, "OPKSSH_TEST_EXAMPLE_VAR") {
						parts := strings.SplitN(v, "=", 2)
						os.Unsetenv(parts[0])
					}
				}
			}()

			mockFs := afero.NewMemMapFs()
			tempDir, _ := afero.TempDir(mockFs, "opk", "config")
			for name, content := range tt.configFile {
				err := afero.WriteFile(mockFs, filepath.Join(tempDir, name), []byte(content), tt.permission)
				require.NoError(t, err)
			}

			ver := VerifyCmd{
				Fs:            mockFs,
				ConfigPathArg: filepath.Join(tempDir, "server_config.yml"),
				filePermChecker: files.PermsChecker{
					Fs: mockFs,
					CmdRunner: func(name string, arg ...string) ([]byte, error) {
						return []byte(tt.owner + " " + tt.group), nil
					},
				},
			}
			err := ver.ReadFromServerConfig()

			require.ErrorContains(t, err, tt.errorString)
		})
	}
}
