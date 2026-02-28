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

package files

import (
	"fmt"
	"io/fs"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

func TestPermissionsChecker(t *testing.T) {
	tests := []struct {
		name             string
		filePath         string
		filePathExpected string
		perms            fs.FileMode
		permsExpected    fs.FileMode
		owner            string
		ownerExpected    string
		group            string
		groupExpected    string
		cmdError         error
		errorExpected    string
	}{
		{
			name:             "simple happy path (all match)",
			filePath:         "/test_file",
			filePathExpected: "/test_file",
			perms:            0777,
			permsExpected:    0777,
			owner:            "testOwner",
			ownerExpected:    "testOwner",
			group:            "testGroup",
			groupExpected:    "testGroup",
			cmdError:         nil,
			errorExpected:    "",
		},
		{
			name:             "simple happy path (owner not checked)",
			filePath:         "/test_file",
			filePathExpected: "/test_file",
			perms:            0777,
			permsExpected:    0777,
			owner:            "testOwner",
			ownerExpected:    "",
			group:            "testGroup",
			groupExpected:    "testGroup",
			cmdError:         nil,
			errorExpected:    "",
		},
		{
			name:             "simple happy path (group not checked)",
			filePath:         "/test_file",
			filePathExpected: "/test_file",
			perms:            0777,
			permsExpected:    0777,
			owner:            "testOwner",
			ownerExpected:    "testOwner",
			group:            "testGroup",
			groupExpected:    "",
			cmdError:         nil,
			errorExpected:    "",
		},
		{
			name:             "simple happy path (only perm checked)",
			filePath:         "/test_file",
			filePathExpected: "/test_file",
			perms:            0777,
			permsExpected:    0777,
			owner:            "testOwner",
			ownerExpected:    "",
			group:            "testGroup",
			groupExpected:    "",
			cmdError:         nil,
			errorExpected:    "",
		},
		{
			name:             "error (owner doesn't match)",
			filePath:         "/test_file",
			filePathExpected: "/test_file",
			perms:            0777,
			permsExpected:    0777,
			owner:            "testOwner",
			ownerExpected:    "testDiffOwner",
			group:            "testGroup",
			groupExpected:    "",
			cmdError:         nil,
			errorExpected:    "expected owner (testDiffOwner), got (testOwner)",
		},
		{
			name:             "error (owner doesn't match)",
			filePath:         "/test_file",
			filePathExpected: "/test_file",
			perms:            0777,
			permsExpected:    0777,
			owner:            "testOwner",
			ownerExpected:    "",
			group:            "testGroup",
			groupExpected:    "testDiffGroup",
			cmdError:         nil,
			errorExpected:    "expected group (testDiffGroup), got (testGroup)",
		},
		{
			name:             "error (perms don't match)",
			filePath:         "/test_file",
			filePathExpected: "/test_file",
			perms:            0640,
			permsExpected:    0650,
			owner:            "testOwner",
			ownerExpected:    "",
			group:            "testGroup",
			groupExpected:    "",
			cmdError:         nil,
			errorExpected:    "expected one of the following permissions [650], got (640)",
		},
		{
			name:             "error (stat command error)",
			filePath:         "/test_file",
			filePathExpected: "/test_file",
			perms:            0640,
			permsExpected:    0650,
			owner:            "testOwner",
			ownerExpected:    "testDiffGroup",
			group:            "testGroup",
			groupExpected:    "testDiffGroup",
			cmdError:         fmt.Errorf("stat command error"),
			errorExpected:    "failed to run stat: stat command error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			mockFs := afero.NewMemMapFs()
			permChecker := PermsChecker{
				Fs: mockFs,
				CmdRunner: func(name string, arg ...string) ([]byte, error) {
					if tt.cmdError != nil {
						return nil, tt.cmdError
					}
					return []byte(tt.owner + " " + tt.group), nil
				},
			}

			err := afero.WriteFile(mockFs, tt.filePath, []byte("1234567890"), tt.perms)
			require.NoError(t, err)

			err = permChecker.CheckPerm(tt.filePathExpected, []fs.FileMode{tt.permsExpected}, tt.ownerExpected, tt.groupExpected)
			if tt.errorExpected != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, tt.errorExpected)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
