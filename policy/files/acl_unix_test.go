//go:build !windows
// +build !windows

package files

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

func TestUnixACLVerifier_ModeMatchAndMismatch(t *testing.T) {
	fs := afero.NewMemMapFs()
	_ = fs.MkdirAll("/etc/opk", 0750)
	path := "/etc/opk/auth_id"
	err := afero.WriteFile(fs, path, []byte("test"), 0640)
	require.NoError(t, err)

	v := NewDefaultACLVerifier(fs)

	// Expect correct mode
	report, err := v.VerifyACL(path, ExpectedACL{Mode: 0640})
	require.NoError(t, err)
	require.True(t, report.Exists)
	require.Empty(t, report.Problems)

	// Expect mismatch
	report2, err := v.VerifyACL(path, ExpectedACL{Mode: 0600})
	require.NoError(t, err)
	require.True(t, report2.Exists)
	require.NotEmpty(t, report2.Problems)
}
