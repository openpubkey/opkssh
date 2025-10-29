//go:build windows
// +build windows

package commands

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/openpubkey/opkssh/policy"
	"github.com/openpubkey/opkssh/policy/files"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

func TestAuditCmd_WindowsSkipsUserPolicyEnumeration(t *testing.T) {
	fs := afero.NewMemMapFs()

	providerPath := policy.SystemDefaultProvidersPath
	policyPath := policy.SystemDefaultPolicyPath

	require.NoError(t, fs.MkdirAll(filepath.Dir(providerPath), 0750))
	require.NoError(t, fs.MkdirAll(filepath.Dir(policyPath), 0750))

	providerContent := "https://accounts.google.com google-client-id 24h\n"
	policyContent := "root alice@example.com https://accounts.google.com\n"

	require.NoError(t, afero.WriteFile(fs, providerPath, []byte(providerContent), 0640))
	require.NoError(t, afero.WriteFile(fs, policyPath, []byte(policyContent), 0640))

	stdOut := &bytes.Buffer{}
	errOut := &bytes.Buffer{}

	auditCmd := AuditCmd{
		Fs:              fs,
		Out:             stdOut,
		ErrOut:          errOut,
		ProviderLoader:  &MockProviderLoader{content: providerContent, t: t},
		CurrentUsername: "testuser",
		filePermsChecker: files.PermsChecker{
			Fs: fs,
			CmdRunner: func(name string, arg ...string) ([]byte, error) {
				return []byte("Administrators"), nil
			},
		},
		aclVerifier:    nil,
		ProviderPath:   providerPath,
		PolicyPath:     policyPath,
		SkipUserPolicy: false,
	}

	_, err := auditCmd.Audit("test_version")
	require.NoError(t, err)
	require.Contains(t, errOut.String(), "skipping user policy audit on Windows")
}
