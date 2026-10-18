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

//go:build unix

package commands

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestFindOpkSSHCertsSkipsFIFO(t *testing.T) {
	sshDir := t.TempDir()
	opkDir := filepath.Join(sshDir, opkSSHDirName)
	require.NoError(t, syscall.Mkdir(opkDir, 0o700))
	require.NoError(t, syscall.Mkfifo(filepath.Join(opkDir, "fifo-cert.pub"), 0o600))

	done := make(chan []string)
	go func() {
		certPaths, _ := findOpkSSHCertPaths(sshDir)
		done <- certPaths
	}()
	select {
	case certPaths := <-done:
		require.Empty(t, certPaths)
	case <-time.After(5 * time.Second):
		t.Fatal("findOpkSSHCerts blocked reading a FIFO")
	}
}
