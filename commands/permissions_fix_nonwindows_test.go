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
	mfs := &mockFileSystem{fs: mem}

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
	if !mfs.Created {
		t.Fatalf("expected CreateFile to be called")
	}
	if !mfs.ChmodCalled {
		t.Fatalf("expected Chmod to be called")
	}
	if !mfs.ChownCalled {
		t.Fatalf("expected Chown to be called")
	}
}
