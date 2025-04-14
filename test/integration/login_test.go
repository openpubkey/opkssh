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
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openpubkey/opkssh/commands"
	"github.com/spf13/afero"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestLogin(t *testing.T) {
	// Check that user can login and that valid openpubkey keys are written to
	// the correct places on disk

	// Setup fake OIDC server on localhost
	t.Log("------- setup OIDC server on localhost ------")
	opServer, err := NewFakeOpServer()
	require.NoError(t, err, "failed to create fake OIDC server")
	defer opServer.Close()
	t.Logf("OP server running at %s", opServer.URL)

	// Call login
	t.Log("------- call login cmd ------")
	errCh := make(chan error)
	opkProvider, loginURL, err := opServer.OpkProvider()
	require.NoError(t, err, "failed to create OPK provider")
	go func() {
		loginCmd := commands.LoginCmd{Fs: afero.NewOsFs()}
		err := loginCmd.Login(TestCtx, opkProvider, false, "")
		errCh <- err
	}()

	// Wait for auth callback server on localhost to come up. It should come up
	// when login command is called
	timeoutErr := WaitForServer(TestCtx, fmt.Sprintf("%s://%s", loginURL.Scheme, loginURL.Host), LoginCallbackServerTimeout)
	require.NoError(t, timeoutErr, "login callback server took too long to startup")

	// Do OIDC login
	DoOidcInteractiveLogin(t, nil, loginURL.String(), "test-user@localhost", "verysecure")

	// Wait for interactive login to complete and assert no error occurred
	timeoutCtx, cancel := context.WithTimeout(TestCtx, 3*time.Second)
	defer cancel()
	select {
	case loginErr := <-errCh:
		require.NoError(t, loginErr, "failed login")
	case <-timeoutCtx.Done():
		t.Fatal(timeoutCtx.Err())
	}

	// Expect to find OPK SSH key is written to disk
	pubKey, secKeyFilePath, err := GetOPKSshKey("")
	require.NoError(t, err)
	require.Equal(t, ssh.CertAlgoECDSA256v01, pubKey.Type(), "expected SSH public key to be an ecdsa-sha2-nistp256 certificate")

	// Parse the private key and check that it is the private key for the public
	// key above by signing and verifying a message
	secKeyBytes, err := os.ReadFile(secKeyFilePath)
	require.NoErrorf(t, err, "failed to read SSH secret key at expected path %s", secKeyFilePath)
	secKey, err := ssh.ParsePrivateKey(secKeyBytes)
	require.NoError(t, err, "failed to parse SSH private key")
	msg := []byte("test")
	sig, err := secKey.Sign(rand.Reader, msg)
	require.NoError(t, err, "failed to sign message using parsed SSH private key")
	require.NoError(t, pubKey.Verify(msg, sig), "failed to verify message using parsed OPK SSH public key")
}

func TestLoginCustomKeyPath(t *testing.T) {
	// Check that user can login and that valid openpubkey keys are written to
	// the correct places on disk

	// Setup fake OIDC server on localhost
	t.Log("------- setup OIDC server on localhost ------")
	opServer, err := NewFakeOpServer()
	require.NoError(t, err, "failed to create fake OIDC server")
	defer opServer.Close()
	t.Logf("OP server running at %s", opServer.URL)

	// Call login
	t.Log("------- call login cmd ------")
	errCh := make(chan error)
	opkProvider, loginURL, err := opServer.OpkProvider()
	require.NoError(t, err, "failed to create OPK provider")

	homePath, err := os.UserHomeDir()

	require.NoError(t, err)

	sshPath := filepath.Join(homePath, ".ssh")

	// Make ~/.ssh if folder does not exist
	err = os.MkdirAll(sshPath, os.ModePerm)
	require.NoError(t, err)

	seckeyPath := filepath.Join(sshPath, "opkssh-key")

	go func() {
		loginCmd := commands.LoginCmd{Fs: afero.NewOsFs()}
		err := loginCmd.Login(TestCtx, opkProvider, false, seckeyPath)
		errCh <- err
	}()

	// Wait for auth callback server on localhost to come up. It should come up
	// when login command is called
	timeoutErr := WaitForServer(TestCtx, fmt.Sprintf("%s://%s", loginURL.Scheme, loginURL.Host), LoginCallbackServerTimeout)
	require.NoError(t, timeoutErr, "login callback server took too long to startup")

	// Do OIDC login
	DoOidcInteractiveLogin(t, nil, loginURL.String(), "test-user@localhost", "verysecure")

	// Wait for interactive login to complete and assert no error occurred
	timeoutCtx, cancel := context.WithTimeout(TestCtx, 3*time.Second)
	defer cancel()
	select {
	case loginErr := <-errCh:
		require.NoError(t, loginErr, "failed login")
	case <-timeoutCtx.Done():
		t.Fatal(timeoutCtx.Err())
	}

	// Expect to find OPK SSH key is written to disk
	pubKey, secKeyFilePath, err := GetOPKSshKey(seckeyPath)
	require.NoError(t, err)
	require.Equal(t, ssh.CertAlgoECDSA256v01, pubKey.Type(), "expected SSH public key to be an ecdsa-sha2-nistp256 certificate")

	// Parse the private key and check that it is the private key for the public
	// key above by signing and verifying a message
	secKeyBytes, err := os.ReadFile(secKeyFilePath)
	require.NoErrorf(t, err, "failed to read SSH secret key at expected path %s", secKeyFilePath)
	secKey, err := ssh.ParsePrivateKey(secKeyBytes)
	require.NoError(t, err, "failed to parse SSH private key")
	msg := []byte("test")
	sig, err := secKey.Sign(rand.Reader, msg)
	require.NoError(t, err, "failed to sign message using parsed SSH private key")
	require.NoError(t, pubKey.Verify(msg, sig), "failed to verify message using parsed OPK SSH public key")
}
