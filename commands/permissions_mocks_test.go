package commands

import (
	"io/fs"

	"github.com/openpubkey/opkssh/policy/files"
	"github.com/spf13/afero"
)

// mockFilePermsOps is a shared configurable mock implementing files.FilePermsOps.
// It is used by both Unix and Windows permission fix tests.
type mockFilePermsOps struct {
	Fs          afero.Fs
	Created     bool
	ChmodCalled bool
	ChownCalled bool
	Applied     []files.ACE
}

func (m *mockFilePermsOps) MkdirAllWithPerm(path string, perm fs.FileMode) error {
	return m.Fs.MkdirAll(path, 0750)
}

func (m *mockFilePermsOps) CreateFileWithPerm(path string) (afero.File, error) {
	m.Created = true
	return m.Fs.Create(path)
}

func (m *mockFilePermsOps) WriteFileWithPerm(path string, data []byte, perm fs.FileMode) error {
	return afero.WriteFile(m.Fs, path, data, 0644)
}

func (m *mockFilePermsOps) Chmod(path string, perm fs.FileMode) error {
	m.ChmodCalled = true
	return m.Fs.Chmod(path, 0644)
}

func (m *mockFilePermsOps) Stat(path string) (fs.FileInfo, error) {
	return m.Fs.Stat(path)
}

func (m *mockFilePermsOps) Chown(path string, owner string, group string) error {
	m.ChownCalled = true
	return nil
}

func (m *mockFilePermsOps) ApplyACE(path string, ace files.ACE) error {
	m.Applied = append(m.Applied, ace)
	return nil
}

// mockACLVerifier is a shared configurable mock implementing files.ACLVerifier.
// It is used by both Unix and Windows permission fix tests.
type mockACLVerifier struct {
	Report files.ACLReport
}

func (m *mockACLVerifier) VerifyACL(path string, expected files.ExpectedACL) (files.ACLReport, error) {
	if m.Report.Path == "" {
		// Default: return a minimal successful report
		return files.ACLReport{Path: path, Exists: true}, nil
	}
	return m.Report, nil
}
