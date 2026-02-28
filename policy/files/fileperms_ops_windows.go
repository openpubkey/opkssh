//go:build windows
// +build windows

package files

import (
	"io/fs"

	"github.com/spf13/afero"
)

// WindowsFilePermsOps implements FilePermsOps for Windows.
// On Windows, POSIX permission bits and chown semantics do not apply. This
// implementation delegates file operations to the provided afero.Fs and
// performs no-op for owner/group semantics. Later we can extend this to call
// into Win32 APIs or PowerShell/icacls to verify and set ACLs.
type WindowsFilePermsOps struct {
	Fs afero.Fs
}

func NewWindowsFilePermsOps(fs afero.Fs) FilePermsOps {
	return &WindowsFilePermsOps{Fs: fs}
}

func (w *WindowsFilePermsOps) MkdirAllWithPerm(path string, perm fs.FileMode) error {
	// afero on Windows will create directories; perm is informational here
	return w.Fs.MkdirAll(path, perm)
}

func (w *WindowsFilePermsOps) CreateFileWithPerm(path string) (afero.File, error) {
	// Create will create file with default attributes. ACLs should be managed
	// by installer; runtime enforcement via ACL queries can be added later.
	return w.Fs.Create(path)
}

func (w *WindowsFilePermsOps) WriteFileWithPerm(path string, data []byte, perm fs.FileMode) error {
	return afero.WriteFile(w.Fs, path, data, perm)
}

func (w *WindowsFilePermsOps) Chmod(path string, perm fs.FileMode) error {
	// On Windows, Chmod updates read-only attribute via os.Chmod; delegate to Fs
	return w.Fs.Chmod(path, perm)
}

func (w *WindowsFilePermsOps) Stat(path string) (fs.FileInfo, error) {
	return w.Fs.Stat(path)
}

func (w *WindowsFilePermsOps) Chown(path string, owner string, group string) error {
	// No-op on Windows. Owner/group/ACLs should be managed by installer or
	// an explicit ACL helper. Returning nil keeps behavior permissive but
	// allows callers to continue operating.
	return nil
}

func (w *WindowsFilePermsOps) ApplyACE(path string, ace ACE) error {
	// No-op default for simple WindowsFilePermsOps. Use WindowsACLFilePermsOps
	// for icacls-based ACL modifications.
	return nil
}
