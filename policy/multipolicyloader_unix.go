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

package policy

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"syscall"
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
//
// In scenarios with user home directories in NFS and root_squash active, in this case
// root accesses the user home directory as user "nobody" and can not read the
// `~/.opk/auth_id` file. As the username is known, the sudo is using this username
// to read the file as the user instead of root.
// REMINDER: for users defined outside /etc/passwd you need to set CGO_ENABLED=1
// before building opkssh.
//
// The command "opkssh readhome username" returns with exitcode ExitCodeReadHome
// in case it could not access the users auth_id file. With this it is possible
// to differentiate between a sudo error and opkssh error.
// sudo without username is not executed on opkssh error.
func ReadWithSudoScript(h *HomePolicyLoader, username string) ([]byte, error) {
	// opkssh readhome ensures the file is not a symlink and has the permissions/ownership.
	// The default path is /usr/local/bin/opkssh
	var err error
	var opkBin string
	opkBin, err = os.Executable()
	if err != nil {
		return nil, fmt.Errorf("error getting opkssh executable path: %w", err)
	}

	var cmd *exec.Cmd
	var homePolicyFileBytes []byte
	if username == "" {
		log.Println("sudo readhome without username")
		cmd = exec.Command("sudo", "-n", opkBin, "readhome", username)
		homePolicyFileBytes, err = cmd.CombinedOutput()
	} else {
		log.Println("sudo with -u ", username)
		if cmd = exec.Command("sudo", "-n", "-u", username, opkBin, "readhome", username); cmd != nil {
			log.Printf("sudo with username %s failed: %v", username, cmd)
		}
		homePolicyFileBytes, err = cmd.CombinedOutput()
		if err != nil {
			var exitError *exec.ExitError
			if errors.As(err, &exitError) {
				status := exitError.Sys().(syscall.WaitStatus)
				log.Printf("sudo exited: %d", status.ExitStatus())
				if status.ExitStatus() < ExitCodeReadHome {
					log.Printf("sudo failed to start, trying without -u ")
					cmd = exec.Command("sudo", "-n", opkBin, "readhome", username)
					homePolicyFileBytes, err = cmd.CombinedOutput()
				} else {
					log.Printf("Failed: opkssh readhome %s", username)
				}
			}
		}
	}

	if err != nil {
		return nil, fmt.Errorf("error reading %s home policy using command %v got output %v and err %v", username, cmd, string(homePolicyFileBytes), err)
	}
	return homePolicyFileBytes, nil
}
