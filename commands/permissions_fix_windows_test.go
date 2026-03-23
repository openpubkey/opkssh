//go:build windows
// +build windows

package commands

import (
	"bytes"
	"io"
	"testing"

	"github.com/openpubkey/opkssh/policy"
	"github.com/openpubkey/opkssh/policy/files"
	"github.com/spf13/afero"
)

func TestRunPermissionsFix_AppliesAdminACE_Windows(t *testing.T) {
	// Setup in-memory fs with system policy file
	mem := afero.NewMemMapFs()
	systemPolicy := policy.SystemDefaultPolicyPath
	afero.WriteFile(mem, systemPolicy, []byte("x"), 0o644)
	// ensure plugins dir exists but no ACEs present
	pluginsDir := policy.GetSystemConfigBasePath() + "/policy.d"
	mem.MkdirAll(pluginsDir, 0o750)
	afero.WriteFile(mem, pluginsDir+"/plugin.yml", []byte("a"), 0o644)

	mfs := &mockFileSystem{
		fs:        mem,
		aclReport: files.ACLReport{Path: systemPolicy, Exists: true, ACEs: []files.ACE{}},
	}

	p := &PermissionsCmd{
		FileSystem:    mfs,
		Out:           &bytes.Buffer{},
		ErrOut:        &bytes.Buffer{},
		IsElevatedFn:  func() (bool, error) { return true, nil },
		ConfirmPrompt: func(prompt string, in io.Reader) (bool, error) { return true, nil },
		Yes:           true,
	}

	err := p.Fix()
	if err != nil {
		t.Fatalf("Fix failed: %v", err)
	}

	if len(mfs.Applied) < 2 {
		t.Fatalf("expected at least 2 ApplyACE calls for Admin and SYSTEM, got %d", len(mfs.Applied))
	}

	// check principals present
	var foundAdmin, foundSystem bool
	for _, a := range mfs.Applied {
		if a.Principal == "Administrators" {
			foundAdmin = true
		}
		if a.Principal == "SYSTEM" {
			foundSystem = true
		}
	}
	if !foundAdmin || !foundSystem {
		t.Fatalf("expected ApplyACE for Administrators and SYSTEM, got: %+v", mfs.Applied)
	}
}
