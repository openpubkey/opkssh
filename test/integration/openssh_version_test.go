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

//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/openpubkey/opkssh/test/integration/ssh_server"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
)

// TestOpenSSHVersionDetection checks that opkssh's package-manager based
// OpenSSH version detection works on the distribution of this CI job.
//
// It runs the real opkssh binary inside the SSH server image that the other
// integration tests already build (so the image comes from the Docker build
// cache).
func TestOpenSSHVersionDetection(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Docker-based integration tests are not supported on Windows")
	}

	// sysdetails.OSType that opkssh should detect in each job's server image.
	expectedOS := map[string]string{
		"ubuntu":   "debian",
		"centos":   "rhel",
		"arch":     "arch",
		"opensuse": "suse",
	}
	osType := os.Getenv("OS_TYPE")
	wantOS, ok := expectedOS[osType]
	if !ok {
		t.Fatalf("OS_TYPE=%q matches no version-detection case", osType)
	}
	t.Parallel()

	container, err := ssh_server.RunOpkSshContainer(TestCtx, "", "", "", false)
	require.NoError(t, err, "failed to start SSH server container")
	defer func() {
		require.NoError(t, container.Terminate(TestCtx, testcontainers.StopTimeout(time.Millisecond)))
	}()

	run := func(cmd string) string {
		t.Helper()
		code, reader, err := container.Exec(TestCtx, []string{"/bin/sh", "-c", cmd}, tcexec.Multiplexed())
		require.NoError(t, err, "failed to run %q", cmd)
		out, err := io.ReadAll(reader)
		require.NoError(t, err)
		// audit exits 1 because the installer writes the default client IDs;
		// only the JSON on stdout matters here.
		if !strings.HasPrefix(cmd, "/usr/local/bin/opkssh audit") {
			require.Equal(t, 0, code, "%q failed:\n%s", cmd, out)
		}
		return strings.TrimSpace(string(out))
	}

	auditJSON := run("/usr/local/bin/opkssh audit --json --skip-user-policy 2>/dev/null")
	var results struct {
		OpenSSHVersion string `json:"openssh_version"`
		OsInfo         string `json:"os_info"`
	}
	require.NoError(t, json.Unmarshal([]byte(auditJSON), &results), "audit output is not JSON:\n%s", auditJSON)
	t.Logf("opkssh detected OS %q, OpenSSH %q", results.OsInfo, results.OpenSSHVersion)

	require.Equal(t, wantOS, results.OsInfo)
	// The package-manager query yields exactly "OpenSSH_X.Y". Anything longer
	// means detection fell back to `ssh -V`, i.e. the distro query is broken.
	require.Regexp(t, `^OpenSSH_\d+\.\d+$`, results.OpenSSHVersion)

	// Cross-check against the installed binary.
	sshV := run("ssh -V 2>&1")
	m := regexp.MustCompile(`^OpenSSH_(\d+\.\d+)`).FindStringSubmatch(sshV)
	require.NotNil(t, m, "unexpected ssh -V output: %s", sshV)
	require.Equal(t, "OpenSSH_"+m[1], results.OpenSSHVersion, "ssh -V reports %s", sshV)
}

func readAllFromReader(reader io.Reader) ([]byte, error) {
	if reader == nil {
		return nil, fmt.Errorf("reader is nil")
	}
	return io.ReadAll(reader)
}
