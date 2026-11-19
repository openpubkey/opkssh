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

//go:build !windows

package discoverycache

import (
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// validateCacheOwner requires base_dir to be owned by the effective user. This
// also applies to root: when AuthorizedKeysCommandUser is root, a base_dir
// owned by another account would let that account plant a JWKS.
func validateCacheOwner(path string, info fs.FileInfo) error {
	return validateCacheOwnerUID(path, info, os.Geteuid())
}

func validateCacheOwnerUID(path string, info fs.FileInfo, uid int) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if int(stat.Uid) != uid {
		owner := userName(int(stat.Uid))
		return fmt.Errorf("cache base_dir %q is owned by %s, but this process runs as %s. "+
			"The cache must be owned by the account that runs opkssh verify (AuthorizedKeysCommandUser). "+
			"To run cache commands by hand, run them as that account, for example: sudo -u %s opkssh cache check",
			path, owner, userName(uid), owner)
	}
	return nil
}

// userName returns the name of the user with the given uid, or "uid N" if
// it has none.
func userName(uid int) string {
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		return u.Username
	}
	return "uid " + strconv.Itoa(uid)
}
