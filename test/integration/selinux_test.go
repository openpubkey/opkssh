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
	"strings"
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

// TestSELinuxPolicyInstallation verifies that the installer turns a local
// opkssh.te (OPKSSH_LOCAL_TE_FILE) into a loadable policy module for both SSH
// daemon domains used by supported SELinux policies. The containers do not
// need SELinux enforcing on the host: semodule validates and links the
// module against each container's policy store.
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

	t.Parallel()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
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

	runSELinuxContainerCommand(t, container, "dnf install -y checkpolicy policycoreutils selinux-policy-devel policycoreutils-python-utils setools-console")

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
	// exercises the fallback path and Stream 10 loads it directly. The
	// installer gets the repository's opkssh.te through OPKSSH_LOCAL_TE_FILE,
	// the option for installing a local build; wget fails so that nothing
	// is downloaded.
	script := `
set -euo pipefail
export SHUNIT_RUNNING=1
export OPKSSH_LOCAL_TE_FILE=/app/opkssh.te
getenforce() { echo Enforcing; }
restorecon() { :; }
setsebool() { :; }
wget() { echo "unexpected download: wget $*" >&2; return 1; }
source /app/install-linux.sh
output=$(check_selinux 2>&1)
echo "$output"
echo "$output" | grep -Fq 'Installed module for ` + tt.expectedPolicyType + `'
`
	runSELinuxContainerCommand(t, container, script)

	testSELinuxCachePolicy(t, container, tt.expectedPolicyType)
}

// cachePolicyPermissions are the operations opkssh verify performs in the
// JWKS cache directory: create the per-provider directories, list them,
// write a temporary file, set its mode and modification time, rename it into
// place, read it and delete outdated files.
var cachePolicyPermissions = map[string][]string{
	"dir":  {"add_name", "create", "getattr", "open", "read", "remove_name", "search", "setattr", "write"},
	"file": {"create", "getattr", "open", "read", "rename", "setattr", "unlink", "write"},
}

// testSELinuxCachePolicy provisions the JWKS cache with the installer against
// the module installed above, then checks the result: the cache directory and
// every file below it get the opkssh_cache_t label, and the SSH daemon domain
// that runs opkssh verify is allowed every operation in
// cachePolicyPermissions on that type. semanage, matchpathcon and sesearch
// run for real against the container's policy store.
func testSELinuxCachePolicy(t *testing.T, container testcontainers.Container, domain string) {
	// Only the installer call needs bash. restorecon needs an SELinux kernel
	// and the preflight needs the opkssh binary, so both are replaced.
	runSELinuxContainerCommand(t, container, `
set -euo pipefail
export SHUNIT_RUNNING=1
getenforce() { echo Enforcing; }
restorecon() { echo "restorecon $*"; }
runuser() { echo "runuser $*"; }
systemd_running() { return 1; }
systemctl() { echo "systemctl $*"; }
source /app/install-linux.sh
getent group opksshuser >/dev/null || groupadd -r opksshuser
getent passwd opksshuser >/dev/null || useradd -r -g opksshuser opksshuser
mkdir -p /etc/opk /tmp/systemd
CACHE_DIR=/var/cache/opkssh
configure_cache /etc /tmp/systemd
`)

	run := func(cmd ...string) string {
		t.Helper()
		code, out := executeCommandAsUser(t, container, cmd, RootUser)
		require.Equalf(t, 0, code, "%s failed:\n%s", strings.Join(cmd, " "), out)
		return out
	}

	fileContexts := run("semanage", "fcontext", "-l", "-C")
	require.Regexp(t, `(?m)^/var/cache/opkssh\(/\.\*\)\?\s.*:opkssh_cache_t:`, fileContexts,
		"the installer must record a file context for the cache directory")

	for _, path := range []string{
		"/var/cache/opkssh",
		"/var/cache/opkssh/0123abcd/jwks",
		"/var/cache/opkssh/0123abcd/jwks/jwks-0123abcd",
		"/var/cache/opkssh/0123abcd/jwks/tmp-123",
	} {
		require.Contains(t, run("matchpathcon", "-n", path), ":opkssh_cache_t:", "label of %s", path)
	}

	policy := strings.TrimSpace(run("bash", "-c", "ls /etc/selinux/targeted/policy/policy.* | sort -V | tail -n 1"))
	allowed := func(targetType, class, perm string) bool {
		// sesearch prints the rules granting the permission, including
		// rules granted through attributes such as file_type.
		return strings.TrimSpace(run("sesearch", "-A", "-s", domain, "-t", targetType, "-c", class, "-p", perm, policy)) != ""
	}
	for class, perms := range cachePolicyPermissions {
		for _, perm := range perms {
			require.Truef(t, allowed("opkssh_cache_t", class, perm),
				"%s is not allowed %s on opkssh_cache_t %s, which opkssh verify needs for the JWKS cache", domain, perm, class)
		}
	}
	require.False(t, allowed("var_t", "file", "write"),
		"%s can write var_t files, so this test no longer shows that the opkssh_cache_t label is needed", domain)
}

func runSELinuxContainerCommand(t *testing.T, container testcontainers.Container, script string) {
	t.Helper()
	exitCode, reader, err := container.Exec(context.Background(), []string{"/bin/bash", "-c", script})
	require.NoError(t, err, "run command in SELinux test container")
	output, err := readAllFromReader(reader)
	require.NoError(t, err, "read SELinux test command output")
	require.Equalf(t, 0, exitCode, "SELinux test command failed:\n%s", output)
}
