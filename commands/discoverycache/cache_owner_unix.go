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
	"syscall"
)

func validateCacheOwner(path string, info fs.FileInfo) error {
	if os.Geteuid() == 0 {
		return nil
	}
	return validateCacheOwnerUID(path, info, os.Geteuid())
}

func validateCacheOwnerUID(path string, info fs.FileInfo, uid int) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if int(stat.Uid) != uid {
		return fmt.Errorf("cache base_dir %q must be owned by the verification user", path)
	}
	return nil
}
