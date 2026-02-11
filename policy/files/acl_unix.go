//go:build !windows
// +build !windows

package files

import (
	"fmt"
	"github.com/spf13/afero"
	"os/user"
	"strconv"
	"syscall"
)

// UnixACLVerifier implements ACLVerifier for Unix-like systems.
type UnixACLVerifier struct {
	Fs afero.Fs
}

func NewDefaultACLVerifier(fs afero.Fs) ACLVerifier {
	return &UnixACLVerifier{Fs: fs}
}

func (u *UnixACLVerifier) VerifyACL(path string, expected ExpectedACL) (ACLReport, error) {
	r := ACLReport{Path: path}
	if u.Fs == nil {
		u.Fs = afero.NewOsFs()
	}
	fi, err := u.Fs.Stat(path)
	if err != nil {
		// file doesn't exist or other stat error
		r.Exists = false
		r.Problems = append(r.Problems, fmt.Sprintf("open %s: %v", path, err))
		return r, nil
	}
	r.Exists = true
	// Mode bits
	r.Mode = fi.Mode().Perm()
	if expected.Mode != 0 {
		if r.Mode != expected.Mode {
			r.Problems = append(r.Problems, fmt.Sprintf("expected mode %o, got %o", expected.Mode, r.Mode))
		}
	}

	// Owner lookup if available via Sys()
	if statT, ok := fi.Sys().(*syscall.Stat_t); ok {
		uid := strconv.FormatUint(uint64(statT.Uid), 10)
		gid := strconv.FormatUint(uint64(statT.Gid), 10)
		ownerName := ""
		groupName := ""
		if uobj, err := user.LookupId(uid); err == nil {
			ownerName = uobj.Username
		}
		if gobj, err := user.LookupGroupId(gid); err == nil {
			groupName = gobj.Name
		}
		r.Owner = ownerName
		if expected.Owner != "" {
			if ownerName == "" {
				r.Problems = append(r.Problems, fmt.Sprintf("could not determine owner for %s (uid=%s)", path, uid))
			} else if ownerName != expected.Owner {
				r.Problems = append(r.Problems, fmt.Sprintf("expected owner (%s), got (%s)", expected.Owner, ownerName))
			}
		}
		_ = groupName // currently not used in report
	} else {
		// Sys() not available (e.g., in-memory FS); only check owner if not specified
		if expected.Owner != "" {
			// we can't determine owner; report a problem
			r.Problems = append(r.Problems, fmt.Sprintf("owner check requested but Sys() unavailable for %s", path))
		}
	}
	return r, nil
}
