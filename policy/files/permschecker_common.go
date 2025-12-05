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
	"io/fs"
	"os/exec"

	"github.com/spf13/afero"
)

// ModeSystemPerms is the expected permission bits that should be set for opkssh
// system policy files (on Unix: /etc/opk/auth_id, /etc/opk/providers; on Windows: %ProgramData%\opk\auth_id, %ProgramData%\opk\providers).
// This mode means that only the owner of the file can write/read to the file, but the group which
// should be opksshuser can read the file.
const ModeSystemPerms = fs.FileMode(0640)

// ModeHomePerms is the expected permission bits that should be set for opkssh
// user home policy files `~/.opk/auth_id`.
const ModeHomePerms = fs.FileMode(0600)

// PermsChecker contains methods to check the ownership, group
// and file permissions of a file on a Unix-like system (or Windows).
type PermsChecker struct {
	Fs        afero.Fs
	CmdRunner func(string, ...string) ([]byte, error)
}

func NewPermsChecker(fs afero.Fs) *PermsChecker {
	return &PermsChecker{Fs: fs, CmdRunner: ExecCmd}
}

func ExecCmd(name string, arg ...string) ([]byte, error) {
	cmd := exec.Command(name, arg...)
	return cmd.CombinedOutput()
}
