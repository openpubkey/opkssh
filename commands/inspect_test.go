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

package commands

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/openpubkey/openpubkey/cosigner"
	"github.com/openpubkey/openpubkey/jose"
	"github.com/openpubkey/openpubkey/pktoken"
	pktokenmocks "github.com/openpubkey/openpubkey/pktoken/mocks"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/providers/mocks"
	"github.com/openpubkey/openpubkey/util"
	"github.com/openpubkey/openpubkey/verifier"
	"github.com/openpubkey/opkssh/policy"
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
	tests := []struct {
		name  string
		print func(i *InspectCmd)
		want  string
	}{
		{
			name:  "valid JSON",
			print: func(i *InspectCmd) { i.printJSON([]byte(`{"name":"test","options":["one","two"]}`)) },
			want:  "{\n  \"name\": \"test\",\n  \"options\": [\n    \"one\",\n    \"two\"\n  ]\n}\n",
		},
		{
			name:  "invalid JSON is printed as is",
			print: func(i *InspectCmd) { i.printJSON([]byte(`{"name":`)) },
			want:  "Error unmarshalling JSON: unexpected end of JSON input\n{\"name\":\n",
		},
		{
			name:  "value that can't be marshalled",
			print: func(i *InspectCmd) { i.printJSONObject(map[string]any{"f": func() {}}) },
			want:  "Error pretty-printing: json: unsupported type: func()\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := new(bytes.Buffer)
			tt.print(NewInspectCmd("foo", buf))
			require.True(t, strings.HasPrefix(buf.String(), tt.want), buf.String())
		})
	}
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

			// Verify all section headers appear in order
			sections := []string{
				"--- SSH Certificate Information ---",
				"--- PKToken Structure ---",
				"--- Signature Information ---",
				"--- Token Metadata ---",
				"--- Expiration by Server Policy ---",
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

			// Extensions are printed sorted by name.
			extStart := 9
			var extLines []string
			for i := extStart; i < len(lines); i++ {
				if !strings.HasPrefix(lines[i], "  ") {
					break
				}
				extLines = append(extLines, strings.TrimSpace(lines[i]))
			}

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
		{
			name:        "Path that can't be read",
			input:       t.TempDir(),
			wantError:   true,
			errorString: "error reading input file",
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

func TestInspectExpiration(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name     string
		issuedAt time.Time
		expires  time.Time
		// refreshedExpires, if set, adds a refreshed ID token with this exp.
		refreshedExpires time.Time
		// noTimeClaims sends iat and exp as 0, which the checks treat as missing.
		noTimeClaims bool
		// wantExpired lists the policies that should report expired.
		wantExpired []string
	}{
		{name: "fresh", issuedAt: now, expires: now.Add(time.Hour)},
		{name: "13 hours old", issuedAt: now.Add(-13 * time.Hour), expires: now.Add(time.Hour), wantExpired: []string{"12h"}},
		{name: "3 days old", issuedAt: now.Add(-72 * time.Hour), expires: now.Add(time.Hour), wantExpired: []string{"12h", "24h", "48h"}},
		{name: "8 days old", issuedAt: now.Add(-8 * 24 * time.Hour), expires: now.Add(time.Hour), wantExpired: []string{"12h", "24h", "48h", "1week"}},
		{name: "ID token exp passed", issuedAt: now.Add(-2 * time.Hour), expires: now.Add(-time.Hour), wantExpired: []string{"oidc", "oidc_refreshed"}},
		{name: "ID token exp passed, refreshed ID token valid", issuedAt: now.Add(-2 * time.Hour), expires: now.Add(-time.Hour),
			refreshedExpires: now.Add(time.Hour), wantExpired: []string{"oidc"}},
		{name: "no iat or exp", noTimeClaims: true, wantExpired: []string{"12h", "24h", "48h", "1week", "oidc", "oidc_refreshed"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, err := util.GenKeyPair(jose.ES256)
			require.NoError(t, err)
			if tt.noTimeClaims {
				tt.issuedAt, tt.expires = time.Unix(0, 0), time.Unix(0, 0)
			}
			pkt := unverifiedMockPKToken(t, signer, tt.issuedAt, tt.expires)
			refreshedExpires := tt.expires
			if !tt.refreshedExpires.IsZero() {
				pkt.FreshIDToken = unverifiedMockPKToken(t, signer, now, tt.refreshedExpires).OpToken
				refreshedExpires = tt.refreshedExpires
			}
			sshCertBytes, _, err := createSSHCert(pkt, signer, []string{"guest"})
			require.NoError(t, err)

			buf := new(bytes.Buffer)
			require.NoError(t, NewInspectCmd(string(sshCertBytes), buf).Run())
			output := buf.String()
			section := output[strings.Index(output, "--- Expiration by Server Policy ---"):]

			wantDeadlines := map[string]string{
				"12h":            tt.issuedAt.Add(12 * time.Hour).Format(time.RFC3339),
				"24h":            tt.issuedAt.Add(24 * time.Hour).Format(time.RFC3339),
				"48h":            tt.issuedAt.Add(48 * time.Hour).Format(time.RFC3339),
				"1week":          tt.issuedAt.Add(7 * 24 * time.Hour).Format(time.RFC3339),
				"oidc":           tt.expires.Format(time.RFC3339),
				"oidc_refreshed": refreshedExpires.Format(time.RFC3339),
				"never":          "Never",
			}
			if tt.noTimeClaims {
				for policyName := range wantDeadlines {
					if policyName != "never" {
						wantDeadlines[policyName] = "Unknown"
					}
				}
			}
			for _, policyName := range expirationPolicyNames {
				status := "valid"
				if slices.Contains(tt.wantExpired, policyName) {
					status = "expired"
				}
				requireLineInSection(t, section, `^`+regexp.QuoteMeta(policyName+":")+`\s+`+regexp.QuoteMeta(wantDeadlines[policyName])+`\s+`+status+`$`)
			}
		})
	}
}

// unverifiedMockPKToken makes a PK token with the given iat and exp. Unlike
// Mocks it skips verification, which would reject old or expired tokens.
func unverifiedMockPKToken(t *testing.T, signer crypto.Signer, issuedAt, expires time.Time) *pktoken.PKToken {
	t.Helper()
	idtTemplate := mocks.DefaultIDTokenTemplate()
	idtTemplate.ExtraClaims = map[string]any{"iat": issuedAt.Unix(), "exp": expires.Unix()}
	pkt, _, err := pktokenmocks.GenerateMockPKTokenWithOpts(t, signer, jose.ES256, idtTemplate,
		&pktokenmocks.MockPKTokenOpts{CommitType: providers.CommitTypesEnum.NONCE_CLAIM, CorrectCicHash: true, CorrectCicSig: true})
	require.NoError(t, err)
	return pkt
}

func TestInspectCertificateVariants(t *testing.T) {
	tests := []struct {
		name string
		// cert returns the certificate to inspect.
		cert       func(t *testing.T) []byte
		wantLines  []string
		wantAbsent []string
	}{
		{
			name: "no PK token",
			cert: func(t *testing.T) []byte {
				return resignedOpkSSHCert(t, func(c *ssh.Certificate) { delete(c.Extensions, "openpubkey-pkt") })
			},
			wantLines:  []string{`^No openpubkey-pkt extension found$`},
			wantAbsent: []string{"--- PKToken Structure ---", "--- Expiration by Server Policy ---"},
		},
		{
			name: "host certificate",
			cert: func(t *testing.T) []byte {
				return resignedOpkSSHCert(t, func(c *ssh.Certificate) { c.CertType = ssh.HostCert })
			},
			wantLines: []string{`^Type:\s+Host Certificate$`},
		},
		{
			name: "unknown certificate type",
			cert: func(t *testing.T) []byte {
				return resignedOpkSSHCert(t, func(c *ssh.Certificate) { c.CertType = 7 })
			},
			wantLines: []string{`^Type:\s+Unknown \(7\)$`},
		},
		{
			name: "corrupt PK token",
			cert: func(t *testing.T) []byte {
				return resignedOpkSSHCert(t, func(c *ssh.Certificate) { c.Extensions["openpubkey-pkt"] = "not-a-pk-token" })
			},
			wantLines:  []string{`^Error parsing PKToken: `},
			wantAbsent: []string{"--- Token Metadata ---"},
		},
		{
			name: "cosigned PK token",
			cert: func(t *testing.T) []byte {
				pkt, signer, _ := Mocks(t, ECDSA)
				cos := &cosigner.Cosigner{Alg: jose.ES256, Signer: signer}
				cosToken, err := cos.Cosign(pkt, pktoken.CosignerClaims{
					Issuer: "https://cosigner.example.com", KeyID: "cos-key", Algorithm: jose.ES256, AuthID: "auth",
					AuthTime: time.Now().Unix(), IssuedAt: time.Now().Unix(), Expiration: time.Now().Add(time.Hour).Unix(),
					RedirectURI: "none", Nonce: "nonce", Typ: "COS",
				})
				require.NoError(t, err)
				require.NoError(t, pkt.AddSignature(cosToken, pktoken.COS))
				certBytes, _, err := createSSHCert(pkt, signer, []string{"guest"})
				require.NoError(t, err)
				return certBytes
			},
			wantLines: []string{`^Cosigner Signature \(COS\) exists$`, `^\s+"iss": "https://cosigner\.example\.com",$`},
		},
		{
			name: "refreshed ID token",
			cert: func(t *testing.T) []byte {
				signer, err := util.GenKeyPair(jose.ES256)
				require.NoError(t, err)
				pkt := unverifiedMockPKToken(t, signer, time.Now(), time.Now().Add(time.Hour))
				pkt.FreshIDToken = unverifiedMockPKToken(t, signer, time.Now(), time.Now().Add(2*time.Hour)).OpToken
				certBytes, _, err := createSSHCert(pkt, signer, []string{"guest"})
				require.NoError(t, err)
				return certBytes
			},
			wantLines: []string{`^Refreshed ID Token exists$`},
		},
		{
			name: "refreshed ID token that doesn't parse",
			cert: func(t *testing.T) []byte {
				signer, err := util.GenKeyPair(jose.ES256)
				require.NoError(t, err)
				pkt := unverifiedMockPKToken(t, signer, time.Now(), time.Now().Add(time.Hour))
				pkt.FreshIDToken = []byte("eyJhbGciOiJSUzI1NiJ9.bm90LWpzb24.c2ln") // payload is "not-json"
				certBytes, _, err := createSSHCert(pkt, signer, []string{"guest"})
				require.NoError(t, err)
				return certBytes
			},
			wantLines: []string{`^Refreshed ID Token exists$`, `^Error parsing refreshed ID token: `, `^--- Expiration by Server Policy ---$`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := new(bytes.Buffer)
			require.NoError(t, NewInspectCmd(string(tt.cert(t)), buf).Run())
			output := buf.String()
			require.True(t, strings.HasPrefix(output, "--- SSH Certificate Information ---\n"), output)
			for _, pattern := range tt.wantLines {
				requireLineInSection(t, output, pattern)
			}
			for _, absent := range tt.wantAbsent {
				require.NotContains(t, output, absent)
			}
		})
	}
}

// resignedOpkSSHCert makes an opkssh certificate, applies mutate and signs it again.
func resignedOpkSSHCert(t *testing.T, mutate func(*ssh.Certificate)) []byte {
	t.Helper()
	pkt, signer, _ := Mocks(t, ECDSA)
	certBytes, _, err := createSSHCert(pkt, signer, []string{"guest"})
	require.NoError(t, err)
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(certBytes)
	require.NoError(t, err)
	cert := pubKey.(*ssh.Certificate)
	mutate(cert)
	sshSigner, err := ssh.NewSignerFromSigner(signer)
	require.NoError(t, err)
	require.NoError(t, cert.SignCert(rand.Reader, sshSigner))
	return ssh.MarshalAuthorizedKey(cert)
}

func TestPrintExpirationIDTokenDoesNotParse(t *testing.T) {
	buf := new(bytes.Buffer)
	NewInspectCmd("", buf).printExpiration(&pktoken.PKToken{OpToken: []byte("not-a-jwt")})
	require.True(t, strings.HasPrefix(buf.String(), "Error parsing ID token: "), buf.String())
	require.NotContains(t, buf.String(), "--- Expiration by Server Policy ---")
}

func TestExpirationPolicyNames(t *testing.T) {
	for _, name := range expirationPolicyNames {
		_, err := policy.ProvidersRow{ExpirationPolicy: name}.GetExpirationPolicy()
		require.NoError(t, err, "inspect lists a policy the providers file doesn't accept: %s", name)
	}
	require.Len(t, expirationPolicyNames, reflect.TypeOf(verifier.ExpirationPolicies).NumField(),
		"openpubkey's expiration policies changed; update expirationPolicyNames")
}

func TestPrintExpirationUnknownPolicy(t *testing.T) {
	names := expirationPolicyNames
	expirationPolicyNames = append(slices.Clone(names), "bogus")
	t.Cleanup(func() { expirationPolicyNames = names })

	signer, err := util.GenKeyPair(jose.ES256)
	require.NoError(t, err)
	buf := new(bytes.Buffer)
	NewInspectCmd("", buf).printExpiration(unverifiedMockPKToken(t, signer, time.Now(), time.Now().Add(time.Hour)))
	requireLineInSection(t, buf.String(), `^bogus:\s+invalid expiration policy: bogus$`)
}
