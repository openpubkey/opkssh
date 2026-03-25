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
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

func setupLogoutTestKeys(t *testing.T, mockFs afero.Fs, keyType KeyType) (string, string) {
	t.Helper()

	pkt, signer, _ := Mocks(t, keyType)
	principals := []string{}
	certBytes, seckeySshPem, err := createSSHCert(pkt, signer, principals)
	require.NoError(t, err)

	homePath, err := os.UserHomeDir()
	require.NoError(t, err)
	sshPath := filepath.Join(homePath, ".ssh")

	afs := &afero.Afero{Fs: mockFs}
	err = afs.MkdirAll(sshPath, os.ModePerm)
	require.NoError(t, err)

	var keyFileName string
	switch keyType {
	case ECDSA:
		keyFileName = "id_ecdsa"
	case ED25519:
		keyFileName = "id_ed25519"
	}

	seckeyPath := filepath.Join(sshPath, keyFileName)
	pubkeyPath := seckeyPath + "-cert.pub"

	err = afs.WriteFile(seckeyPath, seckeySshPem, 0o600)
	require.NoError(t, err)

	// Append "openpubkey" comment like writeKeys does
	certBytes = append(certBytes, []byte(" openpubkey")...)
	err = afs.WriteFile(pubkeyPath, certBytes, 0o644)
	require.NoError(t, err)

	return seckeyPath, pubkeyPath
}

func TestLogoutCmd_RemoveDefaultKeys(t *testing.T) {
	keyTypes := []KeyType{ECDSA, ED25519}

	for _, keyType := range keyTypes {
		t.Run("removes "+keyType.String()+" keys", func(t *testing.T) {
			mockFs := afero.NewMemMapFs()
			seckeyPath, pubkeyPath := setupLogoutTestKeys(t, mockFs, keyType)

			output := &bytes.Buffer{}
			logoutCmd := &LogoutCmd{
				Fs:        mockFs,
				OutWriter: output,
			}

			err := logoutCmd.Run()
			require.NoError(t, err)

			// Verify files were removed
			_, err = mockFs.Stat(seckeyPath)
			require.True(t, os.IsNotExist(err), "private key should be removed")

			_, err = mockFs.Stat(pubkeyPath)
			require.True(t, os.IsNotExist(err), "certificate should be removed")

			require.Contains(t, output.String(), "Removed")
			require.Contains(t, output.String(), "Successfully removed 1 opkssh key pair(s)")
		})
	}
}

func TestLogoutCmd_NoKeysFound(t *testing.T) {
	mockFs := afero.NewMemMapFs()
	output := &bytes.Buffer{}
	logoutCmd := &LogoutCmd{
		Fs:        mockFs,
		OutWriter: output,
	}

	err := logoutCmd.Run()
	require.NoError(t, err)
	require.Contains(t, output.String(), "No opkssh keys found to remove")
}

func TestLogoutCmd_SkipsNonOpenpubkeyKeys(t *testing.T) {
	mockFs := afero.NewMemMapFs()
	afs := &afero.Afero{Fs: mockFs}

	homePath, err := os.UserHomeDir()
	require.NoError(t, err)
	sshPath := filepath.Join(homePath, ".ssh")

	err = afs.MkdirAll(sshPath, os.ModePerm)
	require.NoError(t, err)

	// Create a non-openpubkey key pair by using Mocks but writing a different comment
	pkt, signer, _ := Mocks(t, ECDSA)
	principals := []string{}
	certBytes, seckeySshPem, err := createSSHCert(pkt, signer, principals)
	require.NoError(t, err)

	seckeyPath := filepath.Join(sshPath, "id_ecdsa")
	pubkeyPath := seckeyPath + "-cert.pub"

	err = afs.WriteFile(seckeyPath, seckeySshPem, 0o600)
	require.NoError(t, err)

	// Write cert with a non-openpubkey comment
	certBytes = append(certBytes, []byte(" user@host")...)
	err = afs.WriteFile(pubkeyPath, certBytes, 0o644)
	require.NoError(t, err)

	output := &bytes.Buffer{}
	logoutCmd := &LogoutCmd{
		Fs:        mockFs,
		OutWriter: output,
	}

	err = logoutCmd.Run()
	require.NoError(t, err)
	require.Contains(t, output.String(), "No opkssh keys found to remove")

	// Verify files still exist
	_, err = mockFs.Stat(seckeyPath)
	require.NoError(t, err, "private key should still exist")

	_, err = mockFs.Stat(pubkeyPath)
	require.NoError(t, err, "certificate should still exist")
}

func TestLogoutCmd_SpecificKey(t *testing.T) {
	mockFs := afero.NewMemMapFs()
	seckeyPath, pubkeyPath := setupLogoutTestKeys(t, mockFs, ECDSA)

	output := &bytes.Buffer{}
	logoutCmd := &LogoutCmd{
		Fs:         mockFs,
		KeyPathArg: seckeyPath,
		OutWriter:  output,
	}

	err := logoutCmd.Run()
	require.NoError(t, err)

	// Verify files were removed
	_, err = mockFs.Stat(seckeyPath)
	require.True(t, os.IsNotExist(err), "private key should be removed")

	_, err = mockFs.Stat(pubkeyPath)
	require.True(t, os.IsNotExist(err), "certificate should be removed")

	require.Contains(t, output.String(), "Successfully removed opkssh key pair")
}

func TestLogoutCmd_SpecificKeyNotOpenpubkey(t *testing.T) {
	mockFs := afero.NewMemMapFs()
	afs := &afero.Afero{Fs: mockFs}

	homePath, err := os.UserHomeDir()
	require.NoError(t, err)
	sshPath := filepath.Join(homePath, ".ssh")

	err = afs.MkdirAll(sshPath, os.ModePerm)
	require.NoError(t, err)

	pkt, signer, _ := Mocks(t, ECDSA)
	principals := []string{}
	certBytes, seckeySshPem, err := createSSHCert(pkt, signer, principals)
	require.NoError(t, err)

	seckeyPath := filepath.Join(sshPath, "id_ecdsa")
	pubkeyPath := seckeyPath + "-cert.pub"

	err = afs.WriteFile(seckeyPath, seckeySshPem, 0o600)
	require.NoError(t, err)

	certBytes = append(certBytes, []byte(" user@host")...)
	err = afs.WriteFile(pubkeyPath, certBytes, 0o644)
	require.NoError(t, err)

	output := &bytes.Buffer{}
	logoutCmd := &LogoutCmd{
		Fs:         mockFs,
		KeyPathArg: seckeyPath,
		OutWriter:  output,
	}

	err = logoutCmd.Run()
	require.Error(t, err)
	require.Contains(t, err.Error(), "was not generated by opkssh")
}

func TestLogoutCmd_OpkSSHDir(t *testing.T) {
	mockFs := afero.NewMemMapFs()
	afs := &afero.Afero{Fs: mockFs}

	homePath, err := os.UserHomeDir()
	require.NoError(t, err)
	opkSSHDir := filepath.Join(homePath, ".ssh", "opkssh")

	err = afs.MkdirAll(opkSSHDir, 0o700)
	require.NoError(t, err)

	pkt, signer, _ := Mocks(t, ECDSA)
	principals := []string{}
	certBytes, seckeySshPem, err := createSSHCert(pkt, signer, principals)
	require.NoError(t, err)

	keyName := "accounts.example.com-test_client_id"
	seckeyPath := filepath.Join(opkSSHDir, keyName)
	pubkeyPath := seckeyPath + "-cert.pub"

	err = afs.WriteFile(seckeyPath, seckeySshPem, 0o600)
	require.NoError(t, err)

	// Write cert with openpubkey comment (like writeKeysComment does)
	certBytes = append(certBytes, []byte(" openpubkey: https://accounts.example.com test_client_id")...)
	err = afs.WriteFile(pubkeyPath, certBytes, 0o644)
	require.NoError(t, err)

	// Create config file with IdentityFile entry
	configContent := "IdentityFile " + seckeyPath + "\n"
	configPath := filepath.Join(opkSSHDir, "config")
	err = afs.WriteFile(configPath, []byte(configContent), 0o600)
	require.NoError(t, err)

	output := &bytes.Buffer{}
	logoutCmd := &LogoutCmd{
		Fs:        mockFs,
		OutWriter: output,
	}

	err = logoutCmd.Run()
	require.NoError(t, err)

	// Verify key files were removed
	_, err = mockFs.Stat(seckeyPath)
	require.True(t, os.IsNotExist(err), "private key should be removed")

	_, err = mockFs.Stat(pubkeyPath)
	require.True(t, os.IsNotExist(err), "certificate should be removed")

	// Verify config was cleaned up
	configBytes, err := afs.ReadFile(configPath)
	require.NoError(t, err)
	require.NotContains(t, string(configBytes), seckeyPath)

	require.Contains(t, output.String(), "Removed")
	require.Contains(t, output.String(), "Successfully removed 1 opkssh key pair(s)")
}

func TestLogoutCmd_MultipleKeys(t *testing.T) {
	mockFs := afero.NewMemMapFs()

	// Setup both ECDSA and ED25519 keys
	setupLogoutTestKeys(t, mockFs, ECDSA)
	setupLogoutTestKeys(t, mockFs, ED25519)

	output := &bytes.Buffer{}
	logoutCmd := &LogoutCmd{
		Fs:        mockFs,
		OutWriter: output,
	}

	err := logoutCmd.Run()
	require.NoError(t, err)
	require.Contains(t, output.String(), "Successfully removed 2 opkssh key pair(s)")
}
