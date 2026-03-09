package commands

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/openpubkey/opkssh/policy"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

func TestPermissionsCheck_MissingSystemPolicyReportsProblem(t *testing.T) {
	vfs := afero.NewMemMapFs()
	out := &bytes.Buffer{}
	p := newTestPermissionsCmd(vfs, out)

	// No system policy file created -> check should report problems
	err := p.Check()
	require.Error(t, err)
}

func TestPermissionsCheck_WithSystemPolicyAndPlugins_Succeeds(t *testing.T) {
	vfs := afero.NewMemMapFs()
	out := &bytes.Buffer{}
	p := newTestPermissionsCmd(vfs, out)

	// Create system policy file and parents under the system config base
	path := policy.SystemDefaultPolicyPath
	base := policy.GetSystemConfigBasePath()
	_ = vfs.MkdirAll(base, 0o750)
	err := afero.WriteFile(vfs, path, []byte("user1 alice@example.com google\n"), 0o640)
	require.NoError(t, err)

	// Create plugins dir and a plugin file
	providersDir := filepath.Join(base, "providers")
	_ = vfs.MkdirAll(providersDir, 0o750)
	pluginsDir := filepath.Join(base, "policy.d")
	_ = vfs.MkdirAll(pluginsDir, 0o750)
	err = afero.WriteFile(vfs, filepath.Join(pluginsDir, "example.yml"), []byte("name: test\ncommand: /bin/true\n"), 0o640)
	require.NoError(t, err)

	err = p.Check()
	require.NoError(t, err)
}

func TestPermissionsFix_DryRun_NoPanic(t *testing.T) {
	vfs := afero.NewMemMapFs()
	out := &bytes.Buffer{}
	p := newTestPermissionsCmd(vfs, out)
	p.DryRun = true
	p.Verbose = true

	// Dry-run should not attempt to change real FS and should return nil
	err := p.Fix()
	require.NoError(t, err)
}
