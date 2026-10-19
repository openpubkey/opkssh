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

//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"runtime"
	"testing"
	"time"

	"github.com/openpubkey/opkssh/test/integration/ssh_server"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
)

type permissionsCheckReport struct {
	Ok       bool                    `json:"ok"`
	Problems []string                `json:"problems"`
	Files    []permissionsCheckEntry `json:"files"`
}

type permissionsCheckEntry struct {
	Path        string   `json:"path"`
	Exists      bool     `json:"exists"`
	PermsErr    string   `json:"perms_error,omitempty"`
	ACLErr      string   `json:"acl_error,omitempty"`
	ACLProblems []string `json:"acl_problems,omitempty"`
}

type permissionsFixResult struct {
	Planned []string `json:"planned"`
	Errors  []string `json:"errors,omitempty"`
	DryRun  bool     `json:"dry_run"`
}

// TestPermissionsJSON checks that `opkssh permissions check|fix --json` on a
// real install print exactly one JSON document on stdout and exit non-zero
// when they find a problem.
func TestPermissionsJSON(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Docker-based integration tests are not supported on Windows")
	}
	t.Parallel()

	container, err := ssh_server.RunOpkSshContainer(TestCtx, "", "", "", false)
	require.NoError(t, err, "failed to start SSH server container")
	defer func() {
		require.NoError(t, container.Terminate(TestCtx, testcontainers.StopTimeout(time.Millisecond)))
	}()

	// run returns the exit code and combined output of argv.
	run := func(argv ...string) (int, []byte) {
		t.Helper()
		code, reader, err := container.Exec(TestCtx, argv, tcexec.Multiplexed())
		require.NoError(t, err, "failed to run %v", argv)
		out, err := io.ReadAll(reader)
		require.NoError(t, err)
		return code, out
	}
	// opksshStdout runs opkssh with args and returns its exit code and stdout
	// only, as `opkssh ... 2>/dev/null` would give a script.
	opksshStdout := func(args string) (int, []byte) {
		t.Helper()
		return run("/bin/sh", "-c", "/usr/local/bin/opkssh "+args+" 2>/dev/null")
	}
	decodeOne := func(out []byte, v any) {
		t.Helper()
		decoder := json.NewDecoder(bytes.NewReader(out))
		decoder.DisallowUnknownFields()
		require.NoError(t, decoder.Decode(v), "stdout is not JSON:\n%s", out)
		require.False(t, decoder.More(), "stdout has more than one JSON document:\n%s", out)
	}
	providersEntry := func(report permissionsCheckReport) permissionsCheckEntry {
		t.Helper()
		for _, e := range report.Files {
			if e.Path == "/etc/opk/providers" {
				return e
			}
		}
		t.Fatalf("no /etc/opk/providers entry in %+v", report.Files)
		return permissionsCheckEntry{}
	}

	code, out := run("chmod", "0644", "/etc/opk/providers")
	require.Equal(t, 0, code, "chmod failed: %s", out)

	code, out = opksshStdout("permissions check --json")
	var broken permissionsCheckReport
	decodeOne(out, &broken)
	require.NotEqual(t, 0, code, "check must fail on a 0644 providers file:\n%s", out)
	require.False(t, broken.Ok)
	require.NotEmpty(t, broken.Problems)
	require.Contains(t, providersEntry(broken).PermsErr, "644")

	code, out = opksshStdout("permissions fix --json")
	require.NotEqual(t, 0, code, "fix --json without --yes must refuse to run")
	require.Empty(t, out)

	code, out = opksshStdout("permissions fix --json --yes")
	var fixed permissionsFixResult
	decodeOne(out, &fixed)
	require.Equal(t, 0, code, "fix failed:\n%s", out)
	require.Empty(t, fixed.Errors)

	code, out = opksshStdout("permissions check --json")
	var repaired permissionsCheckReport
	decodeOne(out, &repaired)
	require.Equal(t, 0, code, "check must pass after fix:\n%s", out)
	require.True(t, repaired.Ok)
	require.Empty(t, repaired.Problems)
	require.Empty(t, providersEntry(repaired).PermsErr)
}
