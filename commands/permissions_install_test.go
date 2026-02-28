package commands

import (
	"testing"

	"github.com/openpubkey/opkssh/policy/files"
	"github.com/spf13/afero"
)

func TestInstallCmd_UsesInjectedRunFunction(t *testing.T) {
	// Arrange: inject a fake run function that records invocation
	called := false
	prev := RunPermissionsFixWithDepsFn
	RunPermissionsFixWithDepsFn = func(ops files.FilePermsOps, av files.ACLVerifier, vfs afero.Fs, dryRun bool, yes bool, verbose bool) error {
		called = true
		// verify that yes is true for installer
		if !yes {
			t.Fatalf("expected yes=true for installer run")
		}
		return nil
	}
	defer func() { RunPermissionsFixWithDepsFn = prev }()

	// Execute the cobra command with 'install'
	cmd := NewPermissionsCmd()
	cmd.SetArgs([]string{"install"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("install command failed: %v", err)
	}
	if !called {
		t.Fatalf("expected RunPermissionsFixWithDepsFn to be called")
	}
}
