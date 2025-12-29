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
	"fmt"
	"io"
	"strings"
	"testing"
	"unicode"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

type OpenSSHVersionTest struct {
	name           string
	containerImage string
	setupCommands  []string
	versionCommand string
	expectedPrefix string
}

func TestOpenSSHVersionDetection(t *testing.T) {
	tests := []OpenSSHVersionTest{
		{
			name:           "Debian/Ubuntu",
			containerImage: "debian:latest",
			setupCommands: []string{
				"apt-get update",
				"apt-get install -y openssh-server sed",
			},
			versionCommand: `version=$(/usr/bin/dpkg-query -W -f='${Version}\n' openssh-server | /bin/sed -E 's/^[0-9]*:?([0-9]+\.[0-9]+).*/\1/'); /bin/echo "OpenSSH_$version"`,
			expectedPrefix: "OpenSSH_",
		},
		{
			name:           "RHEL/CentOS",
			containerImage: "rockylinux:9",
			setupCommands: []string{
				"dnf clean all && dnf makecache && dnf install -y openssh-server sed",
			},
			versionCommand: `version=$(/usr/bin/rpm -q --qf "%{VERSION}\n" openssh-server | /bin/sed -E 's/^([0-9]+\.[0-9]+).*/\1/'); /bin/echo "OpenSSH_$version"`,
			expectedPrefix: "OpenSSH_",
		},
		{
			name:           "SUSE",
			containerImage: "opensuse/leap:16.0",
			setupCommands: []string{
				"zypper refresh",
				"zypper install -y openssh sed",
			},
			versionCommand: `version=$(/usr/bin/rpm -q --qf "%{VERSION}\n" openssh | /bin/sed -E 's/^([0-9]+\.[0-9]+).*/\1/'); /bin/echo "OpenSSH_$version"`,
			expectedPrefix: "OpenSSH_",
		},
		{
			name:           "Arch Linux",
			containerImage: "manjarolinux/base:latest",
			setupCommands: []string{
				"pacman-key --init",
				"pacman-key --populate archlinux manjaro",
				"pacman -Sy --noconfirm --needed manjaro-keyring archlinux-keyring",
				"pacman -Sy --noconfirm --needed openssh sed",
			},
			versionCommand: `version=$(/usr/bin/pacman -Qi openssh | /usr/bin/awk '/^Version/ {print $3}' | /bin/sed -E 's/^([0-9]+\.[0-9]+).*/\1/'); /bin/echo "OpenSSH_$version"`,
			expectedPrefix: "OpenSSH_",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testOpenSSHVersionInContainer(t, tt)
		})
	}
}

func testOpenSSHVersionInContainer(t *testing.T, test OpenSSHVersionTest) {
	ctx := TestCtx

	// Create container request
	req := testcontainers.ContainerRequest{
		Image:           test.containerImage,
		Cmd:             []string{"sleep", "3600"}, // Keep container running
		WaitingFor:      wait.ForLog(""),
		AutoRemove:      true,
		AlwaysPullImage: true,
	}

	// Start container
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err, "failed to start container")
	defer func() {
		if termErr := container.Terminate(ctx); termErr != nil {
			t.Logf("Warning: failed to terminate container: %v", termErr)
		}
	}()

	// Run setup commands
	for _, cmd := range test.setupCommands {
		t.Logf("Running setup command: %s", cmd)
		code, reader, err := container.Exec(ctx, []string{"/bin/bash", "-c", cmd})
		out, err := readAllFromReader(reader)
		success := 0
		require.Equalf(t, success, code, "setup command failed:\n%s", string(out))

		require.NoError(t, err, "failed to read setup command output")
		require.NoError(t, err, "failed to execute setup command")
	}

	// Test the version detection command
	t.Logf("Testing version command: %s", test.versionCommand)
	code, reader, err := container.Exec(ctx, []string{"/bin/sh", "-c", test.versionCommand})
	require.NoError(t, err, "failed to execute version command")
	require.Equal(t, 0, code, "version command failed")

	// Read and validate output
	output, err := readAllFromReader(reader)
	require.NoError(t, err, "failed to read command output")

	// Clean output by keeping only printable ASCII characters
	var cleanedBytes []byte
	for _, b := range output {
		if unicode.IsPrint(rune(b)) && b < 128 {
			cleanedBytes = append(cleanedBytes, b)
		}
	}
	outputStr := strings.TrimSpace(string(cleanedBytes))

	t.Logf("Output: --'%s'--", outputStr)

	// Validate output format - should be OpenSSH_X.Y format
	require.Regexp(t, `^OpenSSH_\d+\.\d+`, outputStr,
		"expected output to match OpenSSH_X.Y format, got: %s", outputStr)

	// Extract version number for logging
	version := strings.TrimPrefix(outputStr, "OpenSSH_")
	t.Logf("✓ Successfully detected OpenSSH version: %s", version)
}

func readAllFromReader(reader io.Reader) ([]byte, error) {
	if reader == nil {
		return nil, fmt.Errorf("reader is nil")
	}
	return io.ReadAll(reader)
}
