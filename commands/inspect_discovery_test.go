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
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func writeTestCert(t *testing.T, path, comment string) {
	t.Helper()
	pkt, signer, _ := Mocks(t, ED25519)
	sshCertBytes, _, err := createSSHCert(pkt, signer, []string{"guest"})
	require.NoError(t, err)
	line := string(sshCertBytes)
	if comment != "" {
		line += " " + comment
	}
	require.NoError(t, os.WriteFile(path, []byte(line+"\n"), 0o644))
}

func writeTestPublicKey(t *testing.T, path, comment string) {
	t.Helper()
	_, signer, _ := Mocks(t, ED25519)
	sshSigner, err := ssh.NewSignerFromSigner(signer)
	require.NoError(t, err)
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshSigner.PublicKey())))
	require.NoError(t, os.WriteFile(path, []byte(line+" "+comment+"\n"), 0o644))
}

func certFile(comment string) func(t *testing.T, path string) {
	return func(t *testing.T, path string) { writeTestCert(t, path, comment) }
}

func publicKeyFile(comment string) func(t *testing.T, path string) {
	return func(t *testing.T, path string) { writeTestPublicKey(t, path, comment) }
}

func textFile(content string) func(t *testing.T, path string) {
	return func(t *testing.T, path string) { require.NoError(t, os.WriteFile(path, []byte(content), 0o600)) }
}

func directory(t *testing.T, path string) { require.NoError(t, os.Mkdir(path, 0o700)) }

func TestFindOpkSSHCerts(t *testing.T) {
	tests := []struct {
		name  string
		file  string
		write func(t *testing.T, path string)
		found bool
	}{
		{name: "identity dir cert", file: "opkssh/issuer-aud-cert.pub", write: certFile("openpubkey: https://issuer aud"), found: true},
		{name: "id_ecdsa cert", file: "id_ecdsa-cert.pub", write: certFile("openpubkey"), found: true},
		{name: "id_ecdsa_sk cert", file: "id_ecdsa_sk-cert.pub", write: certFile("openpubkey"), found: true},
		{name: "id_ed25519 cert", file: "id_ed25519-cert.pub", write: certFile("openpubkey"), found: true},
		{name: "id_ed25519_sk cert", file: "id_ed25519_sk-cert.pub", write: certFile("openpubkey"), found: true},
		{name: "foreign comment in identity dir", file: "opkssh/other-cert.pub", write: certFile("user@host")},
		{name: "foreign comment on default name", file: "id_ed25519-cert.pub", write: certFile("user@host")},
		{name: "no comment", file: "id_ecdsa-cert.pub", write: certFile("")},
		{name: "non-default name in ~/.ssh", file: "id_foo-cert.pub", write: certFile("openpubkey")},
		{name: "identity dir file without -cert.pub", file: "opkssh/issuer-aud.pub", write: certFile("openpubkey: https://issuer aud")},
		{name: "bare public key with openpubkey comment", file: "id_ecdsa-cert.pub", write: publicKeyFile("openpubkey")},
		{name: "private key in identity dir", file: "opkssh/issuer-aud", write: textFile("private key")},
		{name: "identity dir config", file: "opkssh/config", write: textFile("IdentityFile x\n")},
		{name: "directory named -cert.pub", file: "opkssh/dir-cert.pub", write: directory},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sshDir := t.TempDir()
			require.NoError(t, os.Mkdir(filepath.Join(sshDir, opkSSHDirName), 0o700))
			path := filepath.Join(sshDir, filepath.FromSlash(tt.file))
			tt.write(t, path)

			certPaths, readErrs := findOpkSSHCerts(sshDir)
			require.Empty(t, readErrs)
			if tt.found {
				require.Equal(t, []string{path}, certPaths)
			} else {
				require.Empty(t, certPaths)
			}
		})
	}
}

func TestFindOpkSSHCertsSortedAcrossDirs(t *testing.T) {
	sshDir := t.TempDir()
	opkDir := filepath.Join(sshDir, opkSSHDirName)
	require.NoError(t, os.Mkdir(opkDir, 0o700))
	writeTestCert(t, filepath.Join(opkDir, "b-cert.pub"), "openpubkey: https://issuer aud")
	writeTestCert(t, filepath.Join(opkDir, "a-cert.pub"), "openpubkey: https://issuer aud")
	writeTestCert(t, filepath.Join(sshDir, "id_ecdsa-cert.pub"), "openpubkey")

	certPaths, _ := findOpkSSHCerts(sshDir)
	require.Equal(t, []string{
		filepath.Join(sshDir, "id_ecdsa-cert.pub"),
		filepath.Join(opkDir, "a-cert.pub"),
		filepath.Join(opkDir, "b-cert.pub"),
	}, certPaths)
}

// setTestHome points os.UserHomeDir at a new temp dir and returns its ~/.ssh.
func setTestHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	sshDir := filepath.Join(home, ".ssh")
	require.NoError(t, os.MkdirAll(filepath.Join(sshDir, opkSSHDirName), 0o700))
	return sshDir
}

// startAgentWithCerts serves an agent holding one opkssh certificate per
// comment, plus a plain key, and returns the certificates. Mocks clears
// SSH_AUTH_SOCK, so the agent starts after every certificate is made.
func startAgentWithCerts(t *testing.T, comments ...string) []*ssh.Certificate {
	t.Helper()
	keyring := agent.NewKeyring()
	var certs []*ssh.Certificate
	for _, comment := range comments {
		pkt, signer, _ := Mocks(t, ECDSA)
		certBytes, _, err := createSSHCert(pkt, signer, []string{"guest"})
		require.NoError(t, err)
		pubKey, _, _, _, err := ssh.ParseAuthorizedKey(certBytes)
		require.NoError(t, err)
		cert := pubKey.(*ssh.Certificate)
		require.NoError(t, keyring.Add(agent.AddedKey{PrivateKey: signer, Certificate: cert, Comment: comment}))
		certs = append(certs, cert)
	}
	_, plainKey, _ := Mocks(t, ED25519)
	require.NoError(t, keyring.Add(agent.AddedKey{PrivateKey: plainKey, Comment: "plain key"}))
	startTestAgent(t, keyring)
	return certs
}

func TestRunDiscovery(t *testing.T) {
	tests := []struct {
		name string
		// setup prepares sshDir and may return more wanted output.
		// "{ssh}" in any wanted string stands for sshDir.
		setup     func(t *testing.T, sshDir string) []string
		unixAgent bool
		nonRoot   bool
		wantOut   []string
		wantExact string
		wantWarn  string
	}{
		{
			name:      "nothing found",
			setup:     func(t *testing.T, sshDir string) []string { return nil },
			wantExact: "No opkssh certificates found in {ssh}/opkssh or {ssh}\nFor a key written with `opkssh login -i <path>`, run `opkssh inspect <path>-cert.pub`\n",
		},
		{
			name: "certs in both dirs, sorted, blank line between",
			setup: func(t *testing.T, sshDir string) []string {
				writeTestCert(t, filepath.Join(sshDir, opkSSHDirName, "issuer-aud-cert.pub"), "openpubkey: https://issuer aud")
				writeTestCert(t, filepath.Join(sshDir, "id_ed25519-cert.pub"), "openpubkey")
				return nil
			},
			wantOut: []string{
				"=== {ssh}/id_ed25519-cert.pub ===\n--- SSH Certificate Information ---\n",
				"\n\n=== {ssh}/opkssh/issuer-aud-cert.pub ===\n--- SSH Certificate Information ---\n",
				"--- Expiration by Server Policy ---\n",
			},
		},
		{
			name:      "nothing found, agent searched",
			unixAgent: true,
			setup: func(t *testing.T, sshDir string) []string {
				startAgentWithCerts(t)
				return nil
			},
			wantExact: "No opkssh certificates found in {ssh}/opkssh, {ssh} or ssh-agent\nFor a key written with `opkssh login -i <path>`, run `opkssh inspect <path>-cert.pub`\n",
		},
		{
			name:      "agent certs added by login and by ssh-add",
			unixAgent: true,
			setup: func(t *testing.T, sshDir string) []string {
				certs := startAgentWithCerts(t, agentKeyComment, "/home/alice/.ssh/work")
				return []string{
					"=== ssh-agent " + ssh.FingerprintSHA256(certs[0].Key) + " ===\n--- SSH Certificate Information ---\n",
					"=== ssh-agent " + ssh.FingerprintSHA256(certs[1].Key) + " ===\n--- SSH Certificate Information ---\n",
				}
			},
		},
		{
			name: "agent unreachable",
			setup: func(t *testing.T, sshDir string) []string {
				writeTestCert(t, filepath.Join(sshDir, "id_ecdsa-cert.pub"), "openpubkey")
				t.Setenv("SSH_AUTH_SOCK", filepath.Join(sshDir, "no-agent.sock"))
				return nil
			},
			wantOut:  []string{"=== {ssh}/id_ecdsa-cert.pub ===\n"},
			wantWarn: "Warning: could not list ssh-agent certificates ({ssh}/no-agent.sock): ",
		},
		{
			name: "no identity dir",
			setup: func(t *testing.T, sshDir string) []string {
				require.NoError(t, os.Remove(filepath.Join(sshDir, opkSSHDirName)))
				writeTestCert(t, filepath.Join(sshDir, "id_ecdsa-cert.pub"), "openpubkey")
				return nil
			},
			wantOut: []string{"=== {ssh}/id_ecdsa-cert.pub ===\n"},
		},
		{
			name:      "agent socket accepts but never answers",
			unixAgent: true,
			setup: func(t *testing.T, sshDir string) []string {
				writeTestCert(t, filepath.Join(sshDir, "id_ecdsa-cert.pub"), "openpubkey")
				startSilentAgent(t)
				return nil
			},
			wantOut:  []string{"=== {ssh}/id_ecdsa-cert.pub ===\n"},
			wantWarn: "Warning: could not list ssh-agent certificates",
		},
		{
			name:    "unreadable identity dir",
			nonRoot: true,
			setup: func(t *testing.T, sshDir string) []string {
				opkDir := filepath.Join(sshDir, opkSSHDirName)
				writeTestCert(t, filepath.Join(sshDir, "id_ecdsa-cert.pub"), "openpubkey")
				require.NoError(t, os.Chmod(opkDir, 0o000))
				t.Cleanup(func() { _ = os.Chmod(opkDir, 0o700) })
				return nil
			},
			wantOut:  []string{"=== {ssh}/id_ecdsa-cert.pub ===\n"},
			wantWarn: "Warning: open {ssh}/opkssh: permission denied\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.unixAgent && runtime.GOOS == "windows" {
				t.Skip("test agent listens on a unix domain socket")
			}
			if tt.nonRoot && (runtime.GOOS == "windows" || os.Geteuid() == 0) {
				t.Skip("needs Unix permissions enforced for the current user")
			}
			sshDir := setTestHome(t)
			t.Setenv("SSH_AUTH_SOCK", "")
			wantOut := append(tt.wantOut, tt.setup(t, sshDir)...)
			expand := func(s string) string { return strings.ReplaceAll(filepath.FromSlash(s), "{ssh}", sshDir) }

			var out, errOut bytes.Buffer
			inspect := NewInspectCmd("", &out)
			inspect.ErrOutput = &errOut
			require.NoError(t, inspect.RunDiscovery())

			if tt.wantExact != "" {
				require.Equal(t, expand(tt.wantExact), out.String())
			}
			for _, want := range wantOut {
				require.Contains(t, out.String(), expand(want))
			}
			if tt.wantWarn == "" {
				require.Empty(t, errOut.String())
			} else {
				require.Contains(t, errOut.String(), expand(tt.wantWarn))
			}
		})
	}
}

// startSilentAgent serves a socket that accepts connections and never
// replies, like one left behind by a dropped agent forwarding.
func startSilentAgent(t *testing.T) {
	t.Helper()
	sockPath := filepath.Join(t.TempDir(), "silent.sock")
	listener, err := net.Listen("unix", sockPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = conn.Close() })
		}
	}()
	t.Setenv("SSH_AUTH_SOCK", sockPath)
	deadline := agentIODeadline
	agentIODeadline = 100 * time.Millisecond
	t.Cleanup(func() { agentIODeadline = deadline })
}

func TestInspectCmdPrintfFailingWriter(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)
	stdout := os.Stdout
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = stdout })

	NewInspectCmd("foo", alwaysFailingWriter{}).printf("fallback %d\n", 42)
	require.NoError(t, w.Close())
	os.Stdout = stdout

	got, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, "fallback 42\n", string(got))
}

type alwaysFailingWriter struct{}

func (alwaysFailingWriter) Write(p []byte) (int, error) {
	return 0, os.ErrClosed
}
