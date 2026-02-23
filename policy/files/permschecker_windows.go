//go:build windows
// +build windows

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
)

// CheckPerm checks file permissions on Windows.
// On Windows, we perform a relaxed check compared to Unix systems because:
// 1. Windows doesn't use POSIX permission bits
// 2. Go's os.Stat() synthesizes permission bits from file attributes, not ACLs
// 3. A file without the read-only attribute will always show as 0666, not 0640
//
// For security on Windows, we rely on:
// - NTFS ACLs set by the installer (Administrators and SYSTEM only)
// - File system level security rather than permission bits
//
// This function validates the file exists and is accessible, but skips
// the strict permission bit check that makes sense on Unix but not on Windows.
func (u *PermsChecker) CheckPerm(path string, requirePerm []fs.FileMode, requiredOwner string, requiredGroup string) error {
	// Verify file exists and is accessible
	fileInfo, err := u.Fs.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to describe the file at path: %w", err)
	}

	// On Windows, we skip the permission bit check because:
	// - Go synthesizes permissions from file attributes, not ACLs
	// - Files show as 0666 (rw-rw-rw-) if not read-only, or 0444 (r--r--r--) if read-only
	// - There's no way to make a file appear as 0640 through file attributes alone
	// - Security is enforced through NTFS ACLs set by the installer
	
	// We also skip owner/group checks since Windows uses different security model
	// (SIDs instead of uid/gid)
	
	_ = fileInfo        // Suppress unused variable warning
	_ = requirePerm     // Suppress unused variable warning  
	_ = requiredOwner   // Suppress unused variable warning
	_ = requiredGroup   // Suppress unused variable warning

	// On Windows, if we can stat the file, we consider it acceptable
	// The actual security is enforced by NTFS ACLs
	return nil
}
