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

	"github.com/openpubkey/opkssh/policy/files"
	"github.com/spf13/afero"
)

// PermCheckResult contains the results of checking permissions on a single file
// or directory. It is returned by CheckFilePermissions and consumed by both the
// audit and permissions commands.
type PermCheckResult struct {
	// Path is the filesystem path that was checked.
	Path string
	// Exists is true if the file/directory was found on disk.
	Exists bool
	// PermsErr is non-empty when the mode or ownership check failed.
	PermsErr string
	// ACLReport contains detailed ACL information (owner, ACEs, problems).
	// It is nil when no ACLVerifier was provided or the path does not exist.
	ACLReport *files.ACLReport
	// ACLErr is non-nil when VerifyACL itself returned an error.
	ACLErr error
}

// CheckFilePermissions checks the existence, permission mode/ownership, and ACLs
// of the file at path. It centralises the permission-checking logic shared by
// the audit and permissions commands so that both report consistent results.
func CheckFilePermissions(
	vfs afero.Fs,
	checker files.PermsChecker,
	aclVerifier files.ACLVerifier,
	path string,
	permInfo files.PermInfo,
) PermCheckResult {
	result := PermCheckResult{Path: path}

	// Check existence
	exists, err := afero.Exists(vfs, path)
	if err != nil {
		result.Exists = false
		result.PermsErr = err.Error()
		return result
	}
	if !exists {
		result.Exists = false
		return result
	}
	result.Exists = true

	// Check file mode and ownership
	if err := checker.CheckPerm(path, []fs.FileMode{permInfo.Mode}, permInfo.Owner, permInfo.Group); err != nil {
		result.PermsErr = err.Error()
	}

	// Check ACLs if verifier is available (Windows-specific in practice)
	if aclVerifier != nil {
		report, err := aclVerifier.VerifyACL(path, files.ExpectedACLFromPerm(permInfo))
		result.ACLReport = &report
		result.ACLErr = err
	}

	return result
}
