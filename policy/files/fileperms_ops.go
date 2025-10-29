package files

import (
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/spf13/afero"
)

// FilePermsOps provides an abstraction for creating files/directories and
// setting permissions in a platform-aware way.
type FilePermsOps interface {
	MkdirAllWithPerm(path string, perm fs.FileMode) error
	CreateFileWithPerm(path string) (afero.File, error)
	WriteFileWithPerm(path string, data []byte, perm fs.FileMode) error
	Chmod(path string, perm fs.FileMode) error
	Stat(path string) (fs.FileInfo, error)
	Chown(path string, owner string, group string) error
	// ApplyACE applies a single ACE to the target path. On platforms that
	// don't support ACE modifications, this may be a no-op or return nil.
	ApplyACE(path string, ace ACE) error
}

// OsFilePermsOps is a default implementation that delegates to an afero.Fs
// for filesystem operations and uses os.Chown when required.
type OsFilePermsOps struct {
	Fs afero.Fs
}

func NewDefaultFilePermsOps(fs afero.Fs) FilePermsOps {
	if runtime.GOOS == "windows" {
		// Prefer ACL-capable implementation on Windows
		return NewWindowsACLFilePermsOps(fs)
	}
	return &OsFilePermsOps{Fs: fs}
}

func (o *OsFilePermsOps) MkdirAllWithPerm(path string, perm fs.FileMode) error {
	return o.Fs.MkdirAll(path, perm)
}

func (o *OsFilePermsOps) CreateFileWithPerm(path string) (afero.File, error) {
	// Ensure parent directory exists
	dir := filepath.Dir(path)
	if err := o.Fs.MkdirAll(dir, 0750); err != nil {
		return nil, err
	}
	return o.Fs.Create(path)
}

func (o *OsFilePermsOps) WriteFileWithPerm(path string, data []byte, perm fs.FileMode) error {
	return afero.WriteFile(o.Fs, path, data, perm)
}

func (o *OsFilePermsOps) Chmod(path string, perm fs.FileMode) error {
	return o.Fs.Chmod(path, perm)
}

func (o *OsFilePermsOps) Stat(path string) (fs.FileInfo, error) {
	return o.Fs.Stat(path)
}

func (o *OsFilePermsOps) Chown(path string, owner string, group string) error {
	// If nothing requested, nothing to do
	if owner == "" && group == "" {
		return nil
	}
	// On Windows, mapping POSIX chown isn't meaningful; return nil
	if runtime.GOOS == "windows" {
		return nil
	}
	// Lookup uid/gid
	var uid int
	var gid int
	if owner != "" {
		uobj, err := user.Lookup(owner)
		if err != nil {
			return err
		}
		uid64, err := strconv.ParseInt(uobj.Uid, 10, 32)
		if err != nil {
			return err
		}
		uid = int(uid64)
	}
	if group != "" {
		gobj, err := user.LookupGroup(group)
		if err != nil {
			return err
		}
		gid64, err := strconv.ParseInt(gobj.Gid, 10, 32)
		if err != nil {
			return err
		}
		gid = int(gid64)
	}
	return os.Chown(path, uid, gid)
}

func (o *OsFilePermsOps) ApplyACE(path string, ace ACE) error {
	// POSIX: ACEs are not supported in this abstraction. No-op.
	return nil
}
