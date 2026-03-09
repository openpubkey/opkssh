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

	mops := &mockFilePermsOps{Fs: mem}
	// Verifier returns no ACEs so ApplyACE should be called for Admin and SYSTEM
	mv := &mockACLVerifier{Report: files.ACLReport{Path: systemPolicy, Exists: true, ACEs: []files.ACE{}}}

	p := &PermissionsCmd{
		Fs:            mem,
		Out:           &bytes.Buffer{},
		ErrOut:        &bytes.Buffer{},
		Ops:           mops,
		ACLVerifier:   mv,
		IsElevatedFn:  func() (bool, error) { return true, nil },
		ConfirmPrompt: func(prompt string, in io.Reader) (bool, error) { return true, nil },
		Yes:           true,
	}

	err := p.Fix()
	if err != nil {
		t.Fatalf("Fix failed: %v", err)
	}

	if len(mops.Applied) < 2 {
		t.Fatalf("expected at least 2 ApplyACE calls for Admin and SYSTEM, got %d", len(mops.Applied))
	}

	// check principals present
	var foundAdmin, foundSystem bool
	for _, a := range mops.Applied {
		if a.Principal == "Administrators" {
			foundAdmin = true
		}
		if a.Principal == "SYSTEM" {
			foundSystem = true
		}
	}
	if !foundAdmin || !foundSystem {
		t.Fatalf("expected ApplyACE for Administrators and SYSTEM, got: %+v", mops.Applied)
	}
}
