//go:build !windows
// +build !windows

package commands

import (
	"bytes"
	"io"
	"testing"

	"github.com/spf13/afero"
)

func TestRunPermissionsFix_NonWindows_CreatesAndSetsPerms(t *testing.T) {
	mem := afero.NewMemMapFs()
	mops := &mockFilePermsOps{Fs: mem}
	mv := &mockACLVerifier{}

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
	if !mops.Created {
		t.Fatalf("expected CreateFileWithPerm to be called")
	}
	if !mops.ChmodCalled {
		t.Fatalf("expected Chmod to be called")
	}
	if !mops.ChownCalled {
		t.Fatalf("expected Chown to be called")
	}
}
