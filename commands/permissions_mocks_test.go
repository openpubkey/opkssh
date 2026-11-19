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
		FileSystem: &ownerStubFileSystem{FileSystem: files.NewFileSystem(vfs, files.WithCmdRunner(func(name string, arg ...string) ([]byte, error) {
			return []byte("root opksshuser"), nil
		}))},
		Out:           out,
		ErrOut:        out,
		IsElevatedFn:  func() (bool, error) { return true, nil },
		ConfirmPrompt: func(prompt string, in io.Reader) (bool, error) { return true, nil },
	}
}

// ownerStubFileSystem fills in what an in-memory filesystem can't: owners
// and ACLs. The real Chown and ApplyACE act on the host path, the real ACL
// verifier can't read an owner from an in-memory file, and CheckPerm's mode
// check differs by platform (Windows doesn't check POSIX modes).
type ownerStubFileSystem struct {
	files.FileSystem
	// aclProblems are the ACL problems VerifyACL reports, by path.
	aclProblems map[string][]string
	// permErrors are the errors CheckPerm returns, by path. Other paths use
	// the real CheckPerm.
	permErrors map[string]error
}

func (o *ownerStubFileSystem) Chown(path string, owner string, group string) error {
	return nil
}

func (o *ownerStubFileSystem) ApplyACE(path string, ace files.ACE) error {
	return nil
}

func (o *ownerStubFileSystem) CheckPerm(path string, requirePerm []fs.FileMode, requiredOwner string, requiredGroup string) error {
	if err, ok := o.permErrors[path]; ok {
		return err
	}
	return o.FileSystem.CheckPerm(path, requirePerm, requiredOwner, requiredGroup)
}

func (o *ownerStubFileSystem) VerifyACL(path string, expected files.ExpectedACL) (files.ACLReport, error) {
	return files.ACLReport{
		Path:     path,
		Exists:   true,
		Owner:    expected.Owner,
		Mode:     expected.Mode,
		Problems: o.aclProblems[path],
	}, nil
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
	return m.fs.MkdirAll(path, perm)
}

func (m *mockFileSystem) CreateFile(path string) (afero.File, error) {
	m.Created = true
	return m.fs.Create(path)
}

func (m *mockFileSystem) WriteFile(path string, data []byte, perm fs.FileMode) error {
	return afero.WriteFile(m.fs, path, data, perm)
}

func (m *mockFileSystem) Chmod(path string, perm fs.FileMode) error {
	m.ChmodCalled = true
	return m.fs.Chmod(path, perm)
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
