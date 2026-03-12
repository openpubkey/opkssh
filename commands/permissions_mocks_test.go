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
		FileSystem:    files.NewFileSystem(vfs),
		Out:           out,
		ErrOut:        out,
		IsElevatedFn:  func() (bool, error) { return true, nil },
		ConfirmPrompt: func(prompt string, in io.Reader) (bool, error) { return true, nil },
	}
}

// mockFileSystem is a configurable mock implementing files.FileSystem.
// It wraps an in-memory afero.Fs for real file I/O while tracking
// permission-mutation calls for assertions.
type mockFileSystem struct {
	fs          afero.Fs
	Created     bool
	ChmodCalled bool
	ChownCalled bool
	Applied     []files.ACE
	aclReport   files.ACLReport
}

func (m *mockFileSystem) Stat(path string) (fs.FileInfo, error) {
	return m.fs.Stat(path)
}

func (m *mockFileSystem) Exists(path string) (bool, error) {
	return afero.Exists(m.fs, path)
}

func (m *mockFileSystem) Open(path string) (afero.File, error) {
	return m.fs.Open(path)
}

func (m *mockFileSystem) ReadFile(path string) ([]byte, error) {
	return afero.ReadFile(m.fs, path)
}

func (m *mockFileSystem) MkdirAll(path string, perm fs.FileMode) error {
	return m.fs.MkdirAll(path, 0o750)
}

func (m *mockFileSystem) CreateFile(path string) (afero.File, error) {
	m.Created = true
	return m.fs.Create(path)
}

func (m *mockFileSystem) WriteFile(path string, data []byte, perm fs.FileMode) error {
	return afero.WriteFile(m.fs, path, data, 0o644)
}

func (m *mockFileSystem) Chmod(path string, perm fs.FileMode) error {
	m.ChmodCalled = true
	return m.fs.Chmod(path, 0o644)
}

func (m *mockFileSystem) Chown(path string, owner string, group string) error {
	m.ChownCalled = true
	return nil
}

func (m *mockFileSystem) ApplyACE(path string, ace files.ACE) error {
	m.Applied = append(m.Applied, ace)
	return nil
}

func (m *mockFileSystem) CheckPerm(path string, requirePerm []fs.FileMode, requiredOwner string, requiredGroup string) error {
	return nil
}

func (m *mockFileSystem) VerifyACL(path string, expected files.ExpectedACL) (files.ACLReport, error) {
	if m.aclReport.Path == "" {
		return files.ACLReport{Path: path, Exists: true}, nil
	}
	return m.aclReport, nil
}
