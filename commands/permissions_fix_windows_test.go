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

func TestRunPermissionsFix_AppliesRequiredACEs_Windows(t *testing.T) {
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
		t.Fatalf("expected at least 2 ApplyACE calls for Administrators and opksshuser, got %d", len(mfs.Applied))
	}

	// check principals present
	var foundAdmin, foundOpksshuser bool
	for _, a := range mfs.Applied {
		if a.Principal == "Administrators" && a.Rights == "GENERIC_ALL" {
			foundAdmin = true
		}
		if a.Principal == "opksshuser" && a.Rights == "GENERIC_READ" {
			foundOpksshuser = true
		}
	}
	if !foundAdmin {
		t.Fatalf("expected ApplyACE for Administrators:GENERIC_ALL, got: %+v", mfs.Applied)
	}
	if !foundOpksshuser {
		t.Fatalf("expected ApplyACE for opksshuser:GENERIC_READ, got: %+v", mfs.Applied)
	}
}

func TestRunPermissionsFix_SkipsExistingACEs_Windows(t *testing.T) {
	// Setup in-memory fs with system policy file, ACEs already present
	mem := afero.NewMemMapFs()
	systemPolicy := policy.SystemDefaultPolicyPath
	afero.WriteFile(mem, systemPolicy, []byte("x"), 0o644)

	mfs := &mockFileSystem{
		fs: mem,
		aclReport: files.ACLReport{
			Path:   systemPolicy,
			Exists: true,
			ACEs: []files.ACE{
				{Principal: "Administrators", Rights: "GENERIC_ALL", Type: "allow"},
				{Principal: "opksshuser", Rights: "GENERIC_READ", Type: "allow"},
			},
		},
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

	// No ACEs should have been applied since they already exist
	for _, a := range mfs.Applied {
		if a.Principal == "SYSTEM" {
			t.Fatalf("should not apply SYSTEM ACE, but got: %+v", mfs.Applied)
		}
	}
}

func TestRunPermissionsFix_NoSystemACE_Windows(t *testing.T) {
	// Verify that SYSTEM:F ACE is never applied
	mem := afero.NewMemMapFs()
	systemPolicy := policy.SystemDefaultPolicyPath
	afero.WriteFile(mem, systemPolicy, []byte("x"), 0o644)

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

	for _, a := range mfs.Applied {
		if a.Principal == "SYSTEM" {
			t.Fatalf("SYSTEM ACE should not be applied, but got: %+v", mfs.Applied)
		}
	}
}
