//go:build !windows
// +build !windows

package files

import (
	"github.com/spf13/afero"
)

// NewWindowsACLFilePermsOps is a stub for non-Windows platforms and returns
// the default OsFilePermsOps so code that references this symbol compiles on
// all platforms.
func NewWindowsACLFilePermsOps(fs afero.Fs) FilePermsOps {
	return &OsFilePermsOps{Fs: fs}
}
