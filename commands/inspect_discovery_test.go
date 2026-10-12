// SPDX-License-Identifier: Apache-2.0

package commands

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// writeTestCert writes a fake authorized_key line holding a real SSH
// certificate with the given comment, the same shape opkssh login writes.
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

// TestDiscoverSSHCerts exercises the locations opkssh login writes
// certificates to. A certificate in the opkssh identity directory, one in
// ~/.ssh under a default key name, foreign certificates that must be
// ignored, and unrelated files all live under the same root.
func TestDiscoverSSHCerts(t *testing.T) {
	sshRoot := t.TempDir()

	// The opkssh identity directory with two certs and one private key.
	opkDir := filepath.Join(sshRoot, opkSshDirName)
	require.NoError(t, os.MkdirAll(opkDir, 0o700))
	writeTestCert(t, filepath.Join(opkDir, "issuer-audience1-cert.pub"), "openpubkey: https://issuer aud")
	writeTestCert(t, filepath.Join(opkDir, "another-issuer-cert.pub"), "openpubkey: https://other aud")

	// A bare private key in the identity directory must not be reported
	// even though it parses as an authorized key.
	priv, err := os.OpenFile(filepath.Join(opkDir, "issuer-audience1"), os.O_CREATE|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	require.NoError(t, priv.Close())

	// A default ssh key location cert.
	writeTestCert(t, filepath.Join(sshRoot, "id_ecdsa-cert.pub"), "openpubkey")

	// Foreign certificates that must never be reported: a default ssh key
	// name without the openpubkey comment, and a non-default file name.
	writeTestCert(t, filepath.Join(sshRoot, "id_ed25519-cert.pub"), "user@host")
	writeTestCert(t, filepath.Join(sshRoot, "id_foo-cert.pub"), "openpubkey")

	// A default ssh key name holding a bare public key (not a certificate)
	// must not be reported: discovery only reports certificates.
	_, signer, _ := Mocks(t, ED25519)
	sshSigner, err := ssh.NewSignerFromSigner(signer)
	require.NoError(t, err)
	pub := ssh.MarshalAuthorizedKey(sshSigner.PublicKey())
	require.NoError(t, os.WriteFile(filepath.Join(sshRoot, "id_ecdsa_sk-cert.pub"), pub, 0o644))

	paths, err := discoverSSHCertsIn(sshRoot)
	require.NoError(t, err)

	// Paths are sorted lexically, so the ~/.ssh entry (i...) precedes the
	// identity-directory entries (o...).
	expected := []string{
		filepath.Join(sshRoot, "id_ecdsa-cert.pub"),
		filepath.Join(opkDir, "another-issuer-cert.pub"),
		filepath.Join(opkDir, "issuer-audience1-cert.pub"),
	}
	require.Equal(t, expected, paths, "only the opkssh-generated certificates should be discovered, sorted")
}

// TestDiscoverSSHCertsEmptyRoot pins the no-certs-found path: no error, no
// paths, even when neither directory exists.
func TestDiscoverSSHCertsEmptyRoot(t *testing.T) {
	sshRoot := t.TempDir()

	paths, err := discoverSSHCertsIn(sshRoot)
	require.NoError(t, err)
	require.Empty(t, paths)
}

// TestInspectCmdNoArgRunsDiscovery runs the inspect command with an empty
// target the way main.go now invokes it, and checks the discovered
// certificates are all printed.
func TestInspectCmdNoArgRunsDiscovery(t *testing.T) {
	sshRoot := t.TempDir()
	opkDir := filepath.Join(sshRoot, opkSshDirName)
	require.NoError(t, os.MkdirAll(opkDir, 0o700))
	writeTestCert(t, filepath.Join(opkDir, "issuer-aud-cert.pub"), "openpubkey: https://issuer aud")
	writeTestCert(t, filepath.Join(sshRoot, "id_ed25519-cert.pub"), "openpubkey")

	var buf bytes.Buffer
	inspect := NewInspectCmd("", &buf)
	require.NoError(t, inspect.runDiscoveryIn(sshRoot))

	out := buf.String()
	require.Contains(t, out, filepath.Join(opkDir, "issuer-aud-cert.pub"))
	require.Contains(t, out, filepath.Join(sshRoot, "id_ed25519-cert.pub"))
	require.Contains(t, out, "--- SSH Certificate Information ---")
}

// TestInspectCmdNoArgNoCerts pins the user-facing message when discovery
// finds nothing.
func TestInspectCmdNoArgNoCerts(t *testing.T) {
	sshRoot := t.TempDir()

	var buf bytes.Buffer
	inspect := NewInspectCmd("", &buf)
	require.NoError(t, inspect.runDiscoveryIn(sshRoot))

	require.Contains(t, buf.String(), "No opkssh generated SSH certificates found")
}

// TestInspectCmdPrintfFailingWriter pins the fallback behavior of printf:
// when the configured writer fails, output goes to stdout instead of
// recursing forever (the pre-fix code called itself on a failing writer).
func TestInspectCmdPrintfFailingWriter(t *testing.T) {
	inspect := NewInspectCmd("foo", alwaysFailingWriter{})
	inspect.printf("fallback %d", 42) // must not hang or panic
}

type alwaysFailingWriter struct{}

func (alwaysFailingWriter) Write(p []byte) (int, error) {
	return 0, os.ErrClosed
}
