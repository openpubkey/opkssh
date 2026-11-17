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
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/openpubkey/opkssh/commands"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func loginWithFakeOP(t *testing.T, opServer *FakeOpServer, loginCmd *commands.LoginCmd, seckeyPath string) {
	t.Helper()
	opkProvider, loginURL, err := opServer.OpkProvider()
	require.NoError(t, err)

	errCh := make(chan error, 1)
	go func() { errCh <- loginCmd.Login(TestCtx, opkProvider, false, seckeyPath) }()

	err = WaitForServer(TestCtx, fmt.Sprintf("%s://%s", loginURL.Scheme, loginURL.Host), LoginCallbackServerTimeout)
	require.NoError(t, err)
	DoOidcInteractiveLogin(t, nil, loginURL.String(), "test-user@localhost", "verysecure")

	ctx, cancel := context.WithTimeout(TestCtx, 3*time.Second)
	defer cancel()
	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestInspectFindsLoginCerts(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	sshDir := filepath.Join(home, ".ssh")
	opkDir := filepath.Join(sshDir, "opkssh")
	require.NoError(t, os.MkdirAll(opkDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(opkDir, "config"), nil, 0o600))

	opServer, err := NewFakeOpServer()
	require.NoError(t, err)
	defer opServer.Close()

	loginWithFakeOP(t, opServer, &commands.LoginCmd{Fs: afero.NewOsFs(), KeyTypeArg: commands.ECDSA}, "")
	loginWithFakeOP(t, opServer, &commands.LoginCmd{Fs: afero.NewOsFs(), KeyTypeArg: commands.ED25519, SSHConfigured: true}, "")
	customKey := filepath.Join(home, "keys", "work")
	require.NoError(t, os.MkdirAll(filepath.Dir(customKey), 0o700))
	addToAgent := runtime.GOOS != "windows"
	if addToAgent {
		startTestAgent(t)
	}
	loginWithFakeOP(t, opServer, &commands.LoginCmd{Fs: afero.NewOsFs(), KeyTypeArg: commands.ECDSA, AddKeyToAgent: addToAgent}, customKey)

	opkCerts, err := filepath.Glob(filepath.Join(opkDir, "*-cert.pub"))
	require.NoError(t, err)
	require.Len(t, opkCerts, 1)

	var out, errOut bytes.Buffer
	inspect := commands.NewInspectCmd("", &out)
	inspect.ErrOutput = &errOut
	require.NoError(t, inspect.RunDiscovery())

	output := out.String()
	require.Empty(t, errOut.String())
	require.Contains(t, output, "=== "+filepath.Join(sshDir, "id_ecdsa-cert.pub")+" ===\n")
	require.Contains(t, output, "=== "+opkCerts[0]+" ===\n")
	require.NotContains(t, output, customKey)
	wantCerts := 2
	if addToAgent {
		customCert, err := os.ReadFile(customKey + "-cert.pub")
		require.NoError(t, err)
		pubKey, _, _, _, err := ssh.ParseAuthorizedKey(customCert)
		require.NoError(t, err)
		require.Contains(t, output, "=== ssh-agent "+ssh.FingerprintSHA256(pubKey.(*ssh.Certificate).Key)+" ===\n")
		wantCerts = 3
	}
	require.Equal(t, wantCerts, strings.Count(output, "--- SSH Certificate Information ---"))
	require.Equal(t, wantCerts, strings.Count(output, "Issuer:             "+opServer.URL))
	require.Equal(t, wantCerts, strings.Count(output, "--- Expiration by Server Policy ---"))
}

func startTestAgent(t *testing.T) {
	t.Helper()
	sockPath := filepath.Join(t.TempDir(), "agent.sock")
	listener, err := net.Listen("unix", sockPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	keyring := agent.NewKeyring()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { _ = agent.ServeAgent(keyring, conn) }()
		}
	}()
	t.Setenv("SSH_AUTH_SOCK", sockPath)
}
