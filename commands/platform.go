package commands

import (
	"github.com/openpubkey/opkssh/policy/files"
)

func expectedSystemOwner() string {
	return files.RequiredPerms.SystemPolicy.Owner
}
