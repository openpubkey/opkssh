package commands

import (
	"io/fs"
	"runtime"

	"github.com/openpubkey/opkssh/policy/files"
)

func expectedSystemOwner() string {
	if runtime.GOOS == "windows" {
		return "Administrators"
	}
	return "root"
}

func expectedSystemACL(requiredPerm fs.FileMode) files.ExpectedACL {
	return files.ExpectedACL{
		Owner: expectedSystemOwner(),
		Mode:  requiredPerm,
	}
}

func isWindows() bool {
	return runtime.GOOS == "windows"
}
