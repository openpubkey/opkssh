// SPDX-License-Identifier: Apache-2.0

package commands

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestInspectCmdPrintf(t *testing.T) {
	buf := new(bytes.Buffer)
	inspect := NewInspectCmd("foo", buf)
	inspect.printf("Answer: %d", 42)

	output := buf.String()
	require.Contains(t, output, "Answer: 42")
}

func TestInspectCmdJson(t *testing.T) {
	inputString := `{"name":"test","options":["one","two"]}`
	input := []byte(inputString)
	outputBuf := new(bytes.Buffer)

	inspect := NewInspectCmd("foo", outputBuf)
	inspect.printJSON(input)

	output := outputBuf.String()
	require.Contains(t, output, `"name": "test",`)
	require.Contains(t, output, `"one",`)
	require.Contains(t, output, ` "two"`)
}

func TestInspectSSHCert(t *testing.T) {
	tests := []struct {
		name    string
		keyType KeyType
	}{
		{
			name:    "ECDSA Certificate",
			keyType: ECDSA,
		},
		{
			name:    "ED25519 Certificate",
			keyType: ED25519,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt, signer, _ := Mocks(t, tt.keyType)
			principals := []string{"guest", "dev"}

			sshCertBytes, signKeyBytes, err := createSSHCert(pkt, signer, principals)
			require.NoError(t, err)
			require.NotNil(t, sshCertBytes)
			require.NotNil(t, signKeyBytes)

			buf := new(bytes.Buffer)
			inspect := NewInspectCmd(string(sshCertBytes), buf)

			err = inspect.Run()
			require.NoError(t, err, "Unexpected error")

			output := buf.String()

			// Verify all four section headers appear in order
			sections := []string{
				"--- SSH Certificate Information ---",
				"--- PKToken Structure ---",
				"--- Signature Information ---",
				"--- Token Metadata ---",
			}
			lastIdx := -1
			for _, section := range sections {
				idx := strings.Index(output, section)
				require.Greater(t, idx, lastIdx,
					"section %q not found or out of order in output", section)
				lastIdx = idx
			}

			// Split into lines for line-by-line verification
			lines := strings.Split(output, "\n")

			// --- Verify SSH Certificate Information section ---
			requireLineEquals(t, lines, 0, "--- SSH Certificate Information ---")
			requireLineMatches(t, lines, 1, `^Serial:\s+0$`)
			requireLineMatches(t, lines, 2, `^Type:\s+User Certificate$`)
			requireLineMatches(t, lines, 3, `^Key ID:\s+arthur\.aardvark@example\.com$`)
			requireLineMatches(t, lines, 4, `^Principals:\s+\[guest dev\]$`)
			requireLineMatches(t, lines, 5, `^Valid After:\s+Not set$`)
			requireLineMatches(t, lines, 6, `^Valid Before:\s+Forever$`)
			requireLineMatches(t, lines, 7, `^Critical Options:\s+map\[\]$`)
			requireLineEquals(t, lines, 8, "Extensions:")

			// Extensions are from a map so order is non-deterministic.
			// Collect extension lines until we hit an empty line or section header.
			extStart := 9
			var extLines []string
			for i := extStart; i < len(lines); i++ {
				if !strings.HasPrefix(lines[i], "  ") {
					break
				}
				extLines = append(extLines, strings.TrimSpace(lines[i]))
			}

			// Sort for deterministic comparison
			sort.Strings(extLines)

			expectedExtNames := []string{
				"openpubkey-pkt",
				"permit-X11-forwarding",
				"permit-agent-forwarding",
				"permit-port-forwarding",
				"permit-pty",
				"permit-user-rc",
			}
			require.Len(t, extLines, len(expectedExtNames),
				"expected %d extensions, got %d", len(expectedExtNames), len(extLines))

			for i, extLine := range extLines {
				name := expectedExtNames[i]
				if name == "openpubkey-pkt" {
					require.Regexp(t, `^openpubkey-pkt: \[PKToken data\] \d+ bytes$`, extLine)
				} else {
					// Permit extensions have empty values
					require.Equal(t, name+":", extLine,
						"extension line mismatch")
				}
			}

			// --- Verify PKToken Structure section ---
			require.Contains(t, output, "\n--- PKToken Structure ---\n")
			require.Contains(t, output, "Payload:\n")

			// Verify the PKToken payload contains expected claims
			require.Contains(t, output, `"email": "arthur.aardvark@example.com"`)
			require.Contains(t, output, `"iss":`)
			require.Contains(t, output, `"sub":`)
			require.Contains(t, output, `"aud":`)

			// --- Verify Signature Information section ---
			require.Contains(t, output, "\n--- Signature Information ---\n")
			require.Contains(t, output, "Provider Signature (OP) exists\n")
			require.Contains(t, output, `"alg": "RS256"`)
			require.Contains(t, output, `"kid":`)
			require.Contains(t, output, "Client Signature (CIC) exists\n")
			require.Contains(t, output, `"alg":`)

			// --- Verify Token Metadata section ---
			require.Contains(t, output, "\n--- Token Metadata ---\n")

			// Verify all metadata fields are printed with correct format
			metadataSection := output[strings.Index(output, "--- Token Metadata ---"):]
			requireLineInSection(t, metadataSection, `^Issuer:\s+.+$`)
			requireLineInSection(t, metadataSection, `^Audience:\s+.+$`)
			requireLineInSection(t, metadataSection, `^Subject:\s+.+$`)
			requireLineInSection(t, metadataSection, `^Identity:\s+.+$`)
			requireLineInSection(t, metadataSection, `^Token Hash:\s+.+$`)
			requireLineInSection(t, metadataSection, `^Provider Algorithm:\s+RS256$`)
		})
	}
}

// requireLineEquals checks that the line at index idx exactly equals expected.
func requireLineEquals(t *testing.T, lines []string, idx int, expected string) {
	t.Helper()
	require.Greater(t, len(lines), idx,
		"output has only %d lines, expected line at index %d", len(lines), idx)
	require.Equal(t, expected, lines[idx],
		"line %d mismatch", idx)
}

// requireLineMatches checks that the line at index idx matches the regexp pattern.
func requireLineMatches(t *testing.T, lines []string, idx int, pattern string) {
	t.Helper()
	require.Greater(t, len(lines), idx,
		"output has only %d lines, expected line at index %d", len(lines), idx)
	require.Regexp(t, regexp.MustCompile(pattern), lines[idx],
		"line %d does not match pattern %q", idx, pattern)
}

// requireLineInSection checks that at least one line in the section matches
// the regexp pattern.
func requireLineInSection(t *testing.T, section string, pattern string) {
	t.Helper()
	re := regexp.MustCompile(pattern)
	for _, line := range strings.Split(section, "\n") {
		if re.MatchString(line) {
			return
		}
	}
	require.Fail(t, fmt.Sprintf("no line in section matches pattern %q", pattern))
}

func TestInspectKey(t *testing.T) {
	dummyKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINlDR6KRBqBZ1/UL96ltcZWQC7QTgru/ckbCrA/i3RfI your_email@example.com"

	// Compute expected fingerprint and marshal prefix from the key
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(dummyKey))
	require.NoError(t, err)
	expectedFingerprint := ssh.FingerprintSHA256(pubKey)
	expectedMarshalPrefix := base64.StdEncoding.EncodeToString(pubKey.Marshal())[:20]

	f, err := os.CreateTemp("", "opkssh")
	require.NoError(t, err, "unable to create test file")

	_, err = f.WriteString(dummyKey)
	require.NoError(t, err, "unable to write test file")
	f.Close()
	defer os.Remove(f.Name())

	dummyFile := f.Name()

	expectedOutput := fmt.Sprintf(
		"--- SSH Public Key Information ---\n"+
			"Type: ssh-ed25519\n"+
			"Fingerprint: %s\n"+
			"Marshal (base64): %s...\n",
		expectedFingerprint, expectedMarshalPrefix,
	)

	tests := []struct {
		name        string
		input       string
		wantError   bool
		errorString string
	}{
		{
			name:        "Invalid input",
			input:       "scoobydoowhereareyou",
			wantError:   true,
			errorString: "failed to parse SSH key",
		},
		{
			name:      "Direct input",
			input:     dummyKey,
			wantError: false,
		},
		{
			name:      "File input",
			input:     dummyFile,
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := new(bytes.Buffer)
			inspect := NewInspectCmd(tt.input, buf)

			err := inspect.Run()

			if tt.wantError {
				require.Error(t, err, "Expected error but got none")
				if tt.errorString != "" {
					require.ErrorContains(t, err, tt.errorString, "Got a wrong error message")
				}
			} else {
				require.NoError(t, err, "Unexpected error")

				output := buf.String()
				require.Equal(t, expectedOutput, output,
					"full printed output should match expected format exactly")
			}
		})
	}
}

func TestInspectFormatTime(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name         string
		input        uint64
		outputString string
	}{
		{
			name:         "epoch",
			input:        0,
			outputString: "Not set",
		},
		{
			name:         "forever",
			input:        18446744073709551615,
			outputString: "Forever",
		},
		{
			name:         "regular timestamp",
			input:        uint64(now.Unix()),
			outputString: now.Format(time.RFC3339),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := formatTime(tt.input)
			require.Equal(t, tt.outputString, output)
		})
	}
}
