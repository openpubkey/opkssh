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

package policy

import (
	"fmt"
	"os"
	"os/exec"
)

// ReadWithSudoScript specifies additional way of loading the policy in the
// user's home directory (`~/.opk/auth_id`). This is needed when the
// AuthorizedKeysCommand user does not have privileges to transverse the user's
// home directory. Instead we call run a command which uses special
// sudoers permissions to read the policy file.
//
// Doing this is more secure than simply giving opkssh sudoer access because
// if there was an RCE in opkssh could be triggered an SSH request via
// AuthorizedKeysCommand, the new opkssh process we use to perform the read
// would not be compromised. Thus, the compromised opkssh process could not assume
// full root privileges.
func ReadWithSudoScript(h *HomePolicyLoader, username string) ([]byte, error) {
	// opkssh readhome ensures the file is not a symlink and has the permissions/ownership.
	// The default path is /usr/local/bin/opkssh
	opkBin, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("error getting opkssh executable path: %w", err)
	}
	cmd := exec.Command("sudo", "-n", opkBin, "readhome", username)

	homePolicyFileBytes, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("error reading %s home policy using command %v got output %v and err %v", username, cmd, string(homePolicyFileBytes), err)
	}
	return homePolicyFileBytes, nil
}
