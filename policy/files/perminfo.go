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

// PermInfo describes the expected filesystem permissions for a given resource
// type used by opkssh. It centralises mode, ownership, and existence
// requirements so that they are defined once and consumed by permission
// checking, fixing and auditing code.
type PermInfo struct {
	// Mode is the expected Unix permission bits (e.g. 0640, 0600, 0750).
	Mode fs.FileMode
	// Owner is the expected owner of the file/directory (e.g. "root" on
	// Linux, "Administrators" on Windows). An empty string means ownership
	// is not checked/enforced.
	Owner string
	// Group is the expected group owner (e.g. "opksshuser"). An empty
	// string means group ownership is not checked/enforced.
	Group string
	// MustExist indicates whether the resource is required to exist for the
	// system to function correctly.
	MustExist bool
}

// String returns a human-readable summary of the permission info.
func (p PermInfo) String() string {
	s := fmt.Sprintf("mode=%o", p.Mode)
	if p.Owner != "" {
		s += " owner=" + p.Owner
	}
	if p.Group != "" {
		s += " group=" + p.Group
	}
	if p.MustExist {
		s += " (required)"
	}
	return s
}

// ExpectedACLFromPerm builds an ExpectedACL from a PermInfo.
func ExpectedACLFromPerm(pi PermInfo) ExpectedACL {
	return ExpectedACL{
		Owner: pi.Owner,
		Mode:  pi.Mode,
	}
}
