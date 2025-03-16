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
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"

	"github.com/openpubkey/opkssh/policy/files"
)

// ReadHome is used to read the home policy file for the user with
// the specified username. This is used when opkssh is called by
// AuthorizedKeysCommand as the opksshuser and needs to use sudoer
// access to read the home policy file (`/home/<username>/opk/auth_id`).
// This function is only available on Linux and Darwin because it relies on
// syscall.Stat_t to determine the owner of the file.
func ReadHome(username string) ([]byte, error) {
	if matched, _ := regexp.MatchString("^[a-z0-9_\\-.]+$", username); !matched {
		return nil, fmt.Errorf("%s is not a valid linux username", username)
	}

	userObj, err := user.Lookup(username)
	if err != nil {
		return nil, fmt.Errorf("failed to find user %s", username)
	}
	homePolicyPath := filepath.Join(userObj.HomeDir, ".opk", "auth_id")

	// Security critical: We reading this file as `sudo -u opksshuser`
	// and opksshuser has elevated permissions to read any file whose
	// path matches `/home/*/opk/auth_id`. We need to be cautious we do follow
	// a symlink as it could be to a file the user is not permitted to read.
	// This would not permit the user to read the file, but they might be able
	// to determine the existence of the file. We use O_NOFOLLOW to prevent
	// following symlinks.
	file, err := os.OpenFile(homePolicyPath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("home policy file %s is a symlink, symlink are unsafe in this context", homePolicyPath)
		}
		return nil, fmt.Errorf("failed to open %s, %v", homePolicyPath, err)
	}
	defer file.Close()

	if fileInfo, err := file.Stat(); err != nil {
		return nil, fmt.Errorf("failed to get info on file %s", homePolicyPath)
	} else if stat, ok := fileInfo.Sys().(*syscall.Stat_t); !ok { // This syscall.Stat_t is doesn't work on Windows
		return nil, fmt.Errorf("failed to stat file %s", homePolicyPath)
	} else {
		// We want to ensure that the file is owned by the correct user and has the correct permissions.
		requiredOwnerUid := userObj.Uid
		fileOwnerUID := strconv.FormatUint(uint64(stat.Uid), 10)
		fileOwner, err := user.LookupId(fileOwnerUID)
		if err != nil {
			return nil, fmt.Errorf("failed to find username for UID %s for file %s", fileOwnerUID, homePolicyPath)
		}
		if fileOwnerUID != userObj.Uid || fileOwner.Username != username {
			return nil, fmt.Errorf("unsafe file permissions on %s expected file owner %s (UID %s) got %s (UID %s)",
				homePolicyPath, username, requiredOwnerUid, fileOwner.Username, fileOwnerUID)
		}
		if fileInfo.Mode().Perm() != files.ModeHomePerms {
			return nil, fmt.Errorf("unsafe file permissions for %s got %o expected %o", homePolicyPath, fileInfo.Mode().Perm(), files.ModeHomePerms)
		}
		fileBytes, err := os.ReadFile(homePolicyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read %s, %v", homePolicyPath, err)
		}
		return fileBytes, nil
	}
}
