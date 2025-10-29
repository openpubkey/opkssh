//go:build !windows
// +build !windows

package commands

import (
	"io/fs"
	"testing"

	"github.com/openpubkey/opkssh/policy/files"
	"github.com/spf13/afero"
)

type mockOpsNW struct {
	Fs          afero.Fs
	Created     bool
	ChmodCalled bool
	ChownCalled bool
}

func (m *mockOpsNW) MkdirAllWithPerm(path string, perm fs.FileMode) error {
	return m.Fs.MkdirAll(path, 0750)
}
func (m *mockOpsNW) CreateFileWithPerm(path string) (afero.File, error) {
	m.Created = true
	return m.Fs.Create(path)
}
func (m *mockOpsNW) WriteFileWithPerm(path string, data []byte, perm fs.FileMode) error {
	return afero.WriteFile(m.Fs, path, data, 0644)
}
func (m *mockOpsNW) Chmod(path string, perm fs.FileMode) error {
	m.ChmodCalled = true
	return m.Fs.Chmod(path, 0644)
}
func (m *mockOpsNW) Stat(path string) (fs.FileInfo, error) { return m.Fs.Stat(path) }
func (m *mockOpsNW) Chown(path string, owner string, group string) error {
	m.ChownCalled = true
	return nil
}
func (m *mockOpsNW) ApplyACE(path string, ace files.ACE) error { return nil }

type mockVerifierNW struct{}

func (m *mockVerifierNW) VerifyACL(path string, expected files.ExpectedACL) (files.ACLReport, error) {
	return files.ACLReport{Path: path, Exists: true}, nil
}

func TestRunPermissionsFix_NonWindows_CreatesAndSetsPerms(t *testing.T) {
	mem := afero.NewMemMapFs()
	mops := &mockOpsNW{Fs: mem}
	mv := &mockVerifierNW{}

	// Ensure elevation passes
	prev := IsElevatedFunc
	IsElevatedFunc = func() (bool, error) { return true, nil }
	defer func() { IsElevatedFunc = prev }()

	err := runPermissionsFixWithDeps(mops, mv, mem, false, true, false)
	if err != nil {
		t.Fatalf("runPermissionsFixWithDeps failed: %v", err)
	}
	if !mops.Created {
		t.Fatalf("expected CreateFileWithPerm to be called")
	}
	if !mops.ChmodCalled {
		t.Fatalf("expected Chmod to be called")
	}
	if !mops.ChownCalled {
		t.Fatalf("expected Chown to be called")
	}
}
