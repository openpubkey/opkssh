package commands

import (
	"path/filepath"
	"testing"

	"github.com/openpubkey/opkssh/policy"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

func TestPermissionsCheck_MissingSystemPolicyReportsProblem(t *testing.T) {
	// Use in-memory FS
	DefaultFs = afero.NewMemMapFs()
	defer func() { DefaultFs = nil }()

	// No system policy file created -> check should report problems
	err := runPermissionsCheck()
	require.Error(t, err)
}

func TestPermissionsCheck_WithSystemPolicyAndPlugins_Succeeds(t *testing.T) {
	DefaultFs = afero.NewMemMapFs()
	defer func() { DefaultFs = nil }()

	// Create system policy file and parents under the system config base
	fs := DefaultFs
	path := policy.SystemDefaultPolicyPath
	base := policy.GetSystemConfigBasePath()
	_ = fs.MkdirAll(base, 0750)
	err := afero.WriteFile(fs, path, []byte("user1 alice@example.com google\n"), 0640)
	require.NoError(t, err)

	// Create plugins dir and a plugin file
	providersDir := filepath.Join(base, "providers")
	_ = fs.MkdirAll(providersDir, 0750)
	pluginsDir := filepath.Join(base, "policy.d")
	_ = fs.MkdirAll(pluginsDir, 0750)
	err = afero.WriteFile(fs, filepath.Join(pluginsDir, "example.yml"), []byte("name: test\ncommand: /bin/true\n"), 0640)
	require.NoError(t, err)

	err = runPermissionsCheck()
	require.NoError(t, err)
}

func TestPermissionsFix_DryRun_NoPanic(t *testing.T) {
	DefaultFs = afero.NewMemMapFs()
	defer func() { DefaultFs = nil }()

	// Dry-run should not attempt to change real FS and should return nil
	err := runPermissionsFix(true, false, true)
	require.NoError(t, err)
}
