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
	"os/exec"
	"strings"

	"github.com/spf13/afero"
)

// ModeSystemPerms is the expected permission bits that should be set for opkssh
// system policy files (`/etc/opk/auth_id`, `/etc/opk/providers`). This mode means
// that only the owner of the file can write/read to the file, but the group which
// should be opksshuser can read the file.
const ModeSystemPerms = fs.FileMode(0640)

// ModeHomePerms is the expected permission bits that should be set for opkssh
// user home policy files `~/.opk/auth_id`.
const ModeHomePerms = fs.FileMode(0600)

// PermsChecker contains methods to check the ownership, group
// and file permissions of a file on a Unix-like system.
type PermsChecker struct {
	Fs        afero.Fs
	CmdRunner func(string, ...string) ([]byte, error)
}

func NewPermsChecker(fs afero.Fs) *PermsChecker {
	return &PermsChecker{Fs: fs, CmdRunner: ExecCmd}
}

// CheckPerm checks the file at the given path if it has the desired permissions.
// The argument requirePerm is a list to enable the caller to specify multiple
// permissions only one of which needs to match the permissions on the file.
// If the requiredOwner or requiredGroup are not empty then the function will also
// that the owner and group of the file match the requiredOwner and requiredGroup
// specified and fail if they do not.
func (u *PermsChecker) CheckPerm(path string, requirePerm []fs.FileMode, requiredOwner string, requiredGroup string) error {
	fileInfo, err := u.Fs.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to describe the file at path: %w", err)
	}
	mode := fileInfo.Mode()

	// if the requiredOwner or requiredGroup are specified then run stat and check if they match
	if requiredOwner != "" || requiredGroup != "" {
		statOutput, err := u.CmdRunner("stat", "-c", "%U %G", path)
		if err != nil {
			return fmt.Errorf("failed to run stat: %w", err)
		}

		statOutputSplit := strings.Split(strings.TrimSpace(string(statOutput)), " ")
		statOwner := statOutputSplit[0]
		statGroup := statOutputSplit[1]
		if len(statOutputSplit) != 2 {
			return fmt.Errorf("expected stat command to return 2 values got %d", len(statOutputSplit))
		}

		if requiredOwner != "" {
			if requiredOwner != statOwner {
				return fmt.Errorf("expected owner (%s), got (%s)", requiredOwner, statOwner)
			}
		}
		if requiredGroup != "" {
			if requiredGroup != statGroup {
				return fmt.Errorf("expected group (%s), got (%s)", requiredGroup, statGroup)
			}
		}
	}

	permMatch := false
	requiredPermString := []string{}
	for _, p := range requirePerm {
		requiredPermString = append(requiredPermString, fmt.Sprintf("%o", p.Perm()))
		if mode.Perm() == p {
			permMatch = true
		}
	}
	if !permMatch {
		return fmt.Errorf("expected one of the following permissions [%s], got (%o)", strings.Join(requiredPermString, ", "), mode.Perm())
	}

	return nil
}

func ExecCmd(name string, arg ...string) ([]byte, error) {
	cmd := exec.Command(name, arg...)
	return cmd.CombinedOutput()
}
