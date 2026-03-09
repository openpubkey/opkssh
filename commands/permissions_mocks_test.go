package commands

import (
	"io"
	"io/fs"

	"github.com/openpubkey/opkssh/policy/files"
	"github.com/spf13/afero"
)

// newTestPermissionsCmd creates a PermissionsCmd wired to an in-memory
// filesystem and the given writer. It uses mock-friendly defaults so that
// tests don't need real OS privileges.
func newTestPermissionsCmd(vfs afero.Fs, out io.Writer) *PermissionsCmd {
	return &PermissionsCmd{
		Fs:            vfs,
		Out:           out,
		ErrOut:        out,
		Ops:           files.NewDefaultFilePermsOps(vfs),
		ACLVerifier:   files.NewDefaultACLVerifier(vfs),
		IsElevatedFn:  func() (bool, error) { return true, nil },
		ConfirmPrompt: func(prompt string, in io.Reader) (bool, error) { return true, nil },
	}
}

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
	return m.Fs.MkdirAll(path, 0o750)
}

func (m *mockFilePermsOps) CreateFileWithPerm(path string) (afero.File, error) {
	m.Created = true
	return m.Fs.Create(path)
}

func (m *mockFilePermsOps) WriteFileWithPerm(path string, data []byte, perm fs.FileMode) error {
	return afero.WriteFile(m.Fs, path, data, 0o644)
}

func (m *mockFilePermsOps) Chmod(path string, perm fs.FileMode) error {
	m.ChmodCalled = true
	return m.Fs.Chmod(path, 0o644)
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
