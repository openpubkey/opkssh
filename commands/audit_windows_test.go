//go:build windows
// +build windows

// Copyright 2026 OpenPubkey
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
