package files

import (
	"io/fs"
)

// ACE represents an access control entry (platform-agnostic minimal view)
type ACE struct {
	Principal string
	// PrincipalSID if present contains the raw SID bytes to use when applying
	// the ACE on Windows. When non-nil, implementations should prefer the SID
	// form of TRUSTEE to avoid name-resolution ambiguity.
	PrincipalSID []byte
	Rights       string
	// PrincipalSIDStr contains the textual SID (S-1-5-...) when available.
	PrincipalSIDStr string
	Type            string // Allow or Deny
	Inherited       bool
}

// ExpectedACL contains the expectations for a path's ownership/ACL
type ExpectedACL struct {
	Owner string
	Mode  fs.FileMode // expected mode bits; 0 means ignore
}

// ACLReport is the structured result from verifying ACLs/ownership for a path
type ACLReport struct {
	Path   string
	Exists bool
	Owner  string
	// OwnerSID contains the raw owner SID bytes on Windows when available.
	// On non-Windows platforms this will be nil.
	OwnerSID []byte
	// OwnerSIDStr is the textual SID value (S-1-5-...) when available.
	OwnerSIDStr string
	Mode        fs.FileMode
	ACEs        []ACE
	Problems    []string
}

// ACLVerifier verifies ACLs and ownership for a given path against expectations.
// Implementations are platform-specific (Unix uses syscalls; Windows uses Win32 APIs).
type ACLVerifier interface {
	VerifyACL(path string, expected ExpectedACL) (ACLReport, error)
}
