//go:build !windows
// +build !windows

package commands

import (
	"testing"

	"github.com/spf13/afero"
)

func TestRunPermissionsFix_NonWindows_CreatesAndSetsPerms(t *testing.T) {
	mem := afero.NewMemMapFs()
	mops := &mockFilePermsOps{Fs: mem}
	mv := &mockACLVerifier{}

	// Ensure elevation passes
	prev := IsElevatedFunc
	IsElevatedFunc = func() (bool, error) { return true, nil }
	defer func() { IsElevatedFunc = prev }()

	err := runPermissionsFixWithDeps(mops, mv, mem, false, true, false)
	if err != nil {
		t.Fatalf("runPermissionsFixWithDeps failed: %v", err)
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
