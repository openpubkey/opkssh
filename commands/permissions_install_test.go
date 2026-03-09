package commands

import (
	"bytes"
	"io"
	"testing"

	"github.com/spf13/afero"
)

func TestInstallCmd_ForceYes(t *testing.T) {
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
	}

	// Execute the cobra command with 'install'
	cmd := p.CobraCommand()
	cmd.SetArgs([]string{"install"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("install command failed: %v", err)
	}
	// install sets Yes=true internally; verify fix ran
	if !mops.ChmodCalled {
		t.Fatalf("expected Chmod to be called")
	}
}
