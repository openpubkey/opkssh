// Copyright 2026 OpenPubkey
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/openpubkey/opkssh/internal/projectpath"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
)

type selinuxPolicyTest struct {
	name               string
	image              string
	expectedPolicyType string
}

// TestSELinuxPolicyInstallation verifies that the installer generates a
// loadable policy module for both SSH daemon domains used by supported
// SELinux policies. The containers do not need SELinux enforcing on the host:
// semodule validates and links the module against each container's policy
// store.
func TestSELinuxPolicyInstallation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Docker-based integration tests are not supported on Windows")
	}
	if osType := os.Getenv("OS_TYPE"); osType != "" && osType != "centos" {
		t.Skip("SELinux policy compatibility is covered by the CentOS integration job")
	}

	tests := []selinuxPolicyTest{
		{
			name:               "CentOS Stream 9 sshd_t",
			image:              "quay.io/centos/centos:stream9",
			expectedPolicyType: "sshd_t",
		},
		{
			name:               "CentOS Stream 10 sshd_session_t",
			image:              "quay.io/centos/centos:stream10",
			expectedPolicyType: "sshd_session_t",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testSELinuxPolicyInstallation(t, tt)
		})
	}
}

func testSELinuxPolicyInstallation(t *testing.T, tt selinuxPolicyTest) {
	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:      tt.image,
		Cmd:        []string{"sleep", "infinity"},
		AutoRemove: true,
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err, "start SELinux test container")
	t.Cleanup(func() {
		if termErr := container.Terminate(ctx); termErr != nil {
			t.Logf("Warning: failed to terminate SELinux test container: %v", termErr)
		}
	})

	runSELinuxContainerCommand(t, container, "dnf install -y checkpolicy policycoreutils selinux-policy-devel")

	for _, source := range []string{"opkssh.te", "scripts/install-linux.sh"} {
		err := container.CopyFileToContainer(
			ctx,
			filepath.Join(projectpath.Root, source),
			"/app/"+filepath.Base(source),
			0o644,
		)
		require.NoError(t, err, "copy %s into container", source)
	}

	// Only commands requiring an enforcing kernel are replaced; checkmodule,
	// semodule_package, and semodule are real and link against the
	// container's actual policy store, so Stream 9 (no sshd_session_t type)
	// exercises the fallback path and Stream 10 loads it directly.
	script := `
set -euo pipefail
export SHUNIT_RUNNING=1
getenforce() { echo Enforcing; }
restorecon() { :; }
setsebool() { :; }
wget() { cp /app/opkssh.te "$3"; }
source /app/install-linux.sh
INSTALL_VERSION=local
output=$(check_selinux 2>&1)
echo "$output"
echo "$output" | grep -Fq 'Installed module for ` + tt.expectedPolicyType + `'
`
	runSELinuxContainerCommand(t, container, script)
}

func runSELinuxContainerCommand(t *testing.T, container testcontainers.Container, script string) {
	t.Helper()
	exitCode, reader, err := container.Exec(context.Background(), []string{"/bin/bash", "-c", script})
	require.NoError(t, err, "run command in SELinux test container")
	output, err := readAllFromReader(reader)
	require.NoError(t, err, "read SELinux test command output")
	require.Equalf(t, 0, exitCode, "SELinux test command failed:\n%s", output)
}
