//go:build windows
// +build windows

package commands

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuditCmd_WindowsEnumeratesUserProfiles(t *testing.T) {
	providerContent := "https://accounts.google.com google-client-id 24h\n"
	policyContent := "root alice@example.com https://accounts.google.com\n"

	stdOut := &bytes.Buffer{}
	errOut := &bytes.Buffer{}

	auditCmd := SetupAuditCmdMocks(t, "", providerContent, policyContent)
	auditCmd.Out = stdOut
	auditCmd.ErrOut = errOut
	auditCmd.CurrentUsername = "testuser"
	auditCmd.SkipUserPolicy = false

	totalResults, err := auditCmd.Audit("test_version")
	require.NoError(t, err)
	require.NotNil(t, totalResults)

	// On Windows, user policy enumeration should now use the registry
	// ProfileList instead of skipping. The audit should complete without
	// the old "skipping user policy audit on Windows" message.
	require.NotContains(t, errOut.String(), "skipping user policy audit on Windows")
}

func TestAuditCmd_WindowsSkipUserPolicyFlag(t *testing.T) {
	providerContent := "https://accounts.google.com google-client-id 24h\n"
	policyContent := "root alice@example.com https://accounts.google.com\n"

	stdOut := &bytes.Buffer{}
	errOut := &bytes.Buffer{}

	auditCmd := SetupAuditCmdMocks(t, "", providerContent, policyContent)
	auditCmd.Out = stdOut
	auditCmd.ErrOut = errOut
	auditCmd.CurrentUsername = "testuser"
	auditCmd.SkipUserPolicy = true

	totalResults, err := auditCmd.Audit("test_version")
	require.NoError(t, err)
	require.NotNil(t, totalResults)

	// When SkipUserPolicy is true, no home policy files should be audited
	require.Empty(t, totalResults.HomePolicyFiles)
}
