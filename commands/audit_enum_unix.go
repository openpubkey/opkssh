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

package commands

import (
	"fmt"

	"github.com/spf13/afero"
)

// enumerateUserHomeDirs returns the list of user home directories by reading
// /etc/passwd. This is the Unix implementation.
func (a *AuditCmd) enumerateUserHomeDirs() ([]etcPasswdRow, error) {
	passwdPath := "/etc/passwd"
	exists, err := afero.Exists(a.Fs, passwdPath)
	if err != nil {
		return nil, fmt.Errorf("failed to check /etc/passwd: %w", err)
	}
	if !exists {
		return nil, fmt.Errorf("/etc/passwd not found (needed to enumerate user home policies)")
	}

	etcPasswdContent, err := afero.ReadFile(a.Fs, passwdPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read /etc/passwd: %w", err)
	}

	return getHomeDirsFromEtcPasswd(string(etcPasswdContent)), nil
}
