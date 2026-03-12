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

package files

import (
	"io/fs"

	"github.com/spf13/afero"
)

// FileSystem abstracts all filesystem and permission operations needed by
// the permissions and audit commands. It combines file I/O, permission
// mutations, ownership management, and ACL verification into a single
// mockable interface that hides platform-specific details.
type FileSystem interface {
	// Stat returns file info for the given path.
	Stat(path string) (fs.FileInfo, error)
	// Exists reports whether the path exists.
	Exists(path string) (bool, error)
	// Open opens a file for reading (e.g. directory listing via Readdir).
	Open(path string) (afero.File, error)
	// ReadFile reads the entire contents of a file.
	ReadFile(path string) ([]byte, error)

	// MkdirAll creates a directory and all parents with the given permission.
	MkdirAll(path string, perm fs.FileMode) error
	// CreateFile creates an empty file, creating parent directories as needed.
	CreateFile(path string) (afero.File, error)
	// WriteFile writes data to a file with the given permission.
	WriteFile(path string, data []byte, perm fs.FileMode) error

	// Chmod sets the permission mode bits on a path.
	Chmod(path string, perm fs.FileMode) error
	// Chown sets the owner and group on a path.
	Chown(path string, owner string, group string) error
	// ApplyACE applies a single access control entry to a path.
	ApplyACE(path string, ace ACE) error

	// CheckPerm verifies that the file at path has one of the required
	// permission modes and, optionally, the expected owner and group.
	CheckPerm(path string, requirePerm []fs.FileMode, requiredOwner string, requiredGroup string) error
	// VerifyACL checks ACLs and ownership against expectations.
	VerifyACL(path string, expected ExpectedACL) (ACLReport, error)
}

// defaultFileSystem implements FileSystem by delegating to existing
// platform-specific implementations.
type defaultFileSystem struct {
	afs     afero.Fs
	ops     FilePermsOps
	checker *PermsChecker
	acl     ACLVerifier
}

// NewFileSystem creates a FileSystem backed by an afero.Fs. It wires up
// the appropriate platform-specific implementations for permission
// operations, permission checking, and ACL verification.
func NewFileSystem(afs afero.Fs) FileSystem {
	return &defaultFileSystem{
		afs:     afs,
		ops:     NewDefaultFilePermsOps(afs),
		checker: NewPermsChecker(afs),
		acl:     NewDefaultACLVerifier(afs),
	}
}

func (d *defaultFileSystem) Stat(path string) (fs.FileInfo, error) {
	return d.afs.Stat(path)
}

func (d *defaultFileSystem) Exists(path string) (bool, error) {
	return afero.Exists(d.afs, path)
}

func (d *defaultFileSystem) Open(path string) (afero.File, error) {
	return d.afs.Open(path)
}

func (d *defaultFileSystem) ReadFile(path string) ([]byte, error) {
	return afero.ReadFile(d.afs, path)
}

func (d *defaultFileSystem) MkdirAll(path string, perm fs.FileMode) error {
	return d.ops.MkdirAllWithPerm(path, perm)
}

func (d *defaultFileSystem) CreateFile(path string) (afero.File, error) {
	return d.ops.CreateFileWithPerm(path)
}

func (d *defaultFileSystem) WriteFile(path string, data []byte, perm fs.FileMode) error {
	return d.ops.WriteFileWithPerm(path, data, perm)
}

func (d *defaultFileSystem) Chmod(path string, perm fs.FileMode) error {
	return d.ops.Chmod(path, perm)
}

func (d *defaultFileSystem) Chown(path string, owner string, group string) error {
	return d.ops.Chown(path, owner, group)
}

func (d *defaultFileSystem) ApplyACE(path string, ace ACE) error {
	return d.ops.ApplyACE(path, ace)
}

func (d *defaultFileSystem) CheckPerm(path string, requirePerm []fs.FileMode, requiredOwner string, requiredGroup string) error {
	return d.checker.CheckPerm(path, requirePerm, requiredOwner, requiredGroup)
}

func (d *defaultFileSystem) VerifyACL(path string, expected ExpectedACL) (ACLReport, error) {
	return d.acl.VerifyACL(path, expected)
}
