// Copyright 2025 OpenPubkey
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package commands

import (
	"bytes"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/openpubkey/opkssh/policy"
	"github.com/openpubkey/opkssh/policy/files"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

// TestAuditAndPermissionsCheckConsistency verifies that the audit and
// permissions check commands report consistent results when examining the
// same system policy file. Both commands now use the shared
// CheckFilePermissions function, so their findings should agree.
func TestAuditAndPermissionsCheckConsistency(t *testing.T) {
	t.Parallel()

	// Set up a shared in-memory filesystem with correct permissions.
	// This test verifies that both audit and the shared permission checker
	// report the same results for a well-configured system policy file.
	vfs := afero.NewMemMapFs()
	checker := files.PermsChecker{
		Fs: vfs,
		CmdRunner: func(name string, arg ...string) ([]byte, error) {
			return []byte("root opksshuser"), nil
		},
	}
	aclVerifier := files.NewDefaultACLVerifier(vfs)

	providerPath := policy.SystemDefaultProvidersPath
	policyPath := policy.SystemDefaultPolicyPath
	basePath := policy.GetSystemConfigBasePath()

	require.NoError(t, vfs.MkdirAll(filepath.Dir(providerPath), 0750))
	require.NoError(t, vfs.MkdirAll(filepath.Dir(policyPath), 0750))

	providerContent := "https://accounts.google.com google-client-id 24h\n"
	policyContent := "root alice@example.com https://accounts.google.com\n"

	require.NoError(t, afero.WriteFile(vfs, providerPath, []byte(providerContent), 0640))
	require.NoError(t, afero.WriteFile(vfs, policyPath, []byte(policyContent), 0640))

	// Also create dirs expected by permissions check
	require.NoError(t, vfs.MkdirAll(filepath.Join(basePath, "providers"), 0750))
	require.NoError(t, vfs.MkdirAll(filepath.Join(basePath, "policy.d"), 0750))

	// --- Run shared CheckFilePermissions (used by both commands) ---
	sp := files.RequiredPerms.SystemPolicy
	permResult := CheckFilePermissions(vfs, checker, aclVerifier, policyPath, sp)
	require.True(t, permResult.Exists, "system policy file should exist")
	require.Empty(t, permResult.PermsErr,
		"CheckFilePermissions should report no perms error for correct permissions")

	// --- Run audit command ---
	stdOut := &bytes.Buffer{}
	errOut := &bytes.Buffer{}

	auditCmd := AuditCmd{
		Fs:               vfs,
		Out:              stdOut,
		ErrOut:           errOut,
		ProviderLoader:   &MockProviderLoader{content: providerContent, t: t},
		CurrentUsername:   "testuser",
		filePermsChecker: checker,
		aclVerifier:      aclVerifier,
		ProviderPath:     providerPath,
		PolicyPath:       policyPath,
		SkipUserPolicy:   true,
	}

	totalResults, err := auditCmd.Audit("test_version")
	require.NoError(t, err)
	require.NotNil(t, totalResults)

	// Both should agree: no permission errors for correctly configured file
	require.Empty(t, totalResults.SystemPolicyFile.PermsError,
		"audit should report no perms error for correct permissions")

	// Both should agree on the permission error message
	require.Equal(t, permResult.PermsErr, totalResults.SystemPolicyFile.PermsError,
		"CheckFilePermissions and audit should report the same permission error")
}

// TestAuditAndPermissionsCheckBadPerms verifies that both the audit command
// and CheckFilePermissions detect incorrect file permissions. This test only
// runs on Unix where PermsChecker enforces file mode bits; on Windows,
// permission enforcement is done through ACLs rather than mode bits.
func TestAuditAndPermissionsCheckBadPerms(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows PermsChecker does not enforce mode bits; ACLs are used instead")
	}
	t.Parallel()

	vfs := afero.NewMemMapFs()
	checker := files.PermsChecker{
		Fs: vfs,
		CmdRunner: func(name string, arg ...string) ([]byte, error) {
			return []byte("root opksshuser"), nil
		},
	}
	aclVerifier := files.NewDefaultACLVerifier(vfs)

	providerPath := policy.SystemDefaultProvidersPath
	policyPath := policy.SystemDefaultPolicyPath

	require.NoError(t, vfs.MkdirAll(filepath.Dir(providerPath), 0750))
	require.NoError(t, vfs.MkdirAll(filepath.Dir(policyPath), 0750))

	providerContent := "https://accounts.google.com google-client-id 24h\n"
	policyContent := "root alice@example.com https://accounts.google.com\n"

	require.NoError(t, afero.WriteFile(vfs, providerPath, []byte(providerContent), 0640))
	// Intentionally wrong permissions
	require.NoError(t, afero.WriteFile(vfs, policyPath, []byte(policyContent), 0777))

	sp := files.RequiredPerms.SystemPolicy

	// Both should detect the wrong permissions
	permResult := CheckFilePermissions(vfs, checker, aclVerifier, policyPath, sp)
	require.True(t, permResult.Exists)
	require.NotEmpty(t, permResult.PermsErr, "should detect wrong permissions")

	stdOut := &bytes.Buffer{}
	errOut := &bytes.Buffer{}
	auditCmd := AuditCmd{
		Fs:               vfs,
		Out:              stdOut,
		ErrOut:           errOut,
		ProviderLoader:   &MockProviderLoader{content: providerContent, t: t},
		CurrentUsername:   "testuser",
		filePermsChecker: checker,
		aclVerifier:      aclVerifier,
		ProviderPath:     providerPath,
		PolicyPath:       policyPath,
		SkipUserPolicy:   true,
	}
	totalResults, err := auditCmd.Audit("test_version")
	require.NoError(t, err)
	require.NotEmpty(t, totalResults.SystemPolicyFile.PermsError, "audit should detect wrong permissions")

	// Both should report the same error
	require.Equal(t, permResult.PermsErr, totalResults.SystemPolicyFile.PermsError,
		"CheckFilePermissions and audit should report the same permission error")
}
