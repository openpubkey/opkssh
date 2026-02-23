package commands

import (
	"runtime"

	"github.com/openpubkey/opkssh/policy/files"
)

func expectedSystemOwner() string {
	return files.RequiredPerms.SystemPolicy.Owner
}

func expectedSystemACL(pi files.PermInfo) files.ExpectedACL {
	return files.ExpectedACLFromPerm(pi)
}

func isWindows() bool {
	return runtime.GOOS == "windows"
}
