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
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/jose"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/providers/mocks"
	"github.com/openpubkey/openpubkey/util"
	"github.com/openpubkey/openpubkey/verifier"
	"github.com/openpubkey/opkssh/policy"
	"github.com/openpubkey/opkssh/policy/files"
	"github.com/openpubkey/opkssh/sshcert"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

const userInfoResponse = `{
	"sub": "me",
	"email": "alice@example.com",
	"name": "Alice Example",
	"groups": ["group1", "group2"]
}`

func AllowAllPolicyEnforcer(userDesired string, pkt *pktoken.PKToken, userInfo string, certB64 string, typArg string, denyList policy.DenyList, extraArgs []string) error {
	return nil
}

func AllowIfExpectedUserInfo(userDesired string, pkt *pktoken.PKToken, userInfo string, certB64 string, typArg string, denyList policy.DenyList, extraArgs []string) error {
	if userInfo == "" {
		return fmt.Errorf("userInfo is required")
	} else if len(userInfo) != 93 {
		// Smoke test that something is returned
		return fmt.Errorf("userInfo is not valid, %d", len(userInfo))
	}
	return nil
}

func TestAuthorizedKeysCommand(t *testing.T) {
	t.Parallel()
	expectedAccessToken := "fake-auth-token"

	alg := jose.ES256
	signer, err := util.GenKeyPair(alg)
	require.NoError(t, err)

	providerOpts := providers.DefaultMockProviderOpts()
	providerOpts.Issuer = "https://accounts.google.com"
	op, _, idtTemplate, err := providers.NewMockProvider(providerOpts)
	require.NoError(t, err)

	mockEmail := "arthur.aardvark@example.com"
	idtTemplate.ExtraClaims = map[string]any{
		"email": mockEmail,
	}

	mockExtraArgs := []string{
		"extraArg1",
		"extraArg2",
	}

	// defaultPrincipals is used when a test does not specify principals
	defaultPrincipals := []string{"guest", "dev"}
	// defaultExpectedLine is the authorized_keys line prefix expected for defaultPrincipals
	defaultExpectedLine := "cert-authority,principals=\"guest,dev\" ecdsa-sha2-nistp256"

	tests := []struct {
		name        string
		accessToken string
		errorString string
		policyFunc  func(userDesired string, pkt *pktoken.PKToken, userInfo string, certB64 string, typArg string, denyList policy.DenyList, extraArgs []string) error
		// principals to set in the signed SSH cert. If nil, defaultPrincipals is used.
		// Use an empty non-nil slice to test a cert with no principals.
		principals []string
		// expectedLine is the substring expected in the authorized_keys output.
		// If empty, defaultExpectedLine is used.
		expectedLine string
	}{
		{
			name:       "Happy Path",
			policyFunc: AllowAllPolicyEnforcer,
		},
		{
			name:        "Happy Path (with auth token)",
			accessToken: expectedAccessToken,
			policyFunc:  AllowIfExpectedUserInfo,
		},
		{
			name:        "Wrong auth token",
			accessToken: "Bad-auth-token",
			policyFunc:  AllowIfExpectedUserInfo,
			errorString: "userInfo is required",
		},
		{
			name: "Passes on extraArgs",
			policyFunc: func(userDesired string, pkt *pktoken.PKToken, userInfo string, certB64 string, typArg string, denyList policy.DenyList, extraArgs []string) error {
				if slices.Equal(extraArgs, mockExtraArgs) {
					return nil
				}

				return fmt.Errorf("extraArgs doesn't match (expected %v, got %v)", mockExtraArgs, extraArgs)
			},
		},
		{
			name:         "Happy Path (opkssh-wildcard principal)",
			policyFunc:   AllowAllPolicyEnforcer,
			principals:   []string{"opkssh-wildcard"},
			expectedLine: "cert-authority,principals=\"opkssh-wildcard\" ecdsa-sha2-nistp256",
		},
		{
			name:         "Happy Path (no principals in cert produces bare cert-authority line)",
			policyFunc:   AllowAllPolicyEnforcer,
			principals:   []string{},
			expectedLine: "cert-authority ecdsa-sha2-nistp256",
		},
		{
			name:        "Rejects cert with quote-injection principal",
			policyFunc:  AllowAllPolicyEnforcer,
			principals:  []string{`evil",command="/bin/sh`},
			errorString: "invalid principal",
		},
		{
			name:        "Rejects cert with newline-injection principal",
			policyFunc:  AllowAllPolicyEnforcer,
			principals:  []string{"evil\nssh-ed25519 AAAAattackerkey attacker@evil"},
			errorString: "invalid principal",
		},
		{
			name:        "Rejects cert with comma-splitting principal",
			policyFunc:  AllowAllPolicyEnforcer,
			principals:  []string{"guest,root"},
			errorString: "invalid principal",
		},
		{
			name:        "Rejects cert with one bad principal among valid ones",
			policyFunc:  AllowAllPolicyEnforcer,
			principals:  []string{"guest", "dev", `x"`},
			errorString: "invalid principal",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := client.New(op, client.WithSigner(signer, alg))
			require.NoError(t, err)

			pkt, err := client.Auth(context.Background())
			require.NoError(t, err)

			var accessToken []byte
			if tt.accessToken != "" {
				accessToken = []byte(tt.accessToken)
			} else {
				accessToken = nil
			}

			principals := tt.principals
			if principals == nil {
				principals = defaultPrincipals
			}
			cert, err := sshcert.New(pkt, accessToken, principals)
			require.NoError(t, err)

			sshSigner, err := ssh.NewSignerFromSigner(signer)
			require.NoError(t, err)

			signerMas, err := ssh.NewSignerWithAlgorithms(sshSigner.(ssh.AlgorithmSigner),
				[]string{ssh.KeyAlgoECDSA256})
			require.NoError(t, err)

			sshCert, err := cert.SignCert(signerMas)
			require.NoError(t, err)

			certTypeAndCertB64 := ssh.MarshalAuthorizedKey(sshCert)
			typeArg := strings.Split(string(certTypeAndCertB64), " ")[0]
			certB64Arg := strings.Split(string(certTypeAndCertB64), " ")[1]

			verPkt, err := verifier.New(
				op,
				verifier.WithExpirationPolicy(verifier.ExpirationPolicies.NEVER_EXPIRE),
			)
			require.NoError(t, err)

			userArg := "user"
			ver := VerifyCmd{
				PktVerifier: *verPkt,
				CheckPolicy: tt.policyFunc,
				HttpClient:  mocks.NewMockGoogleUserInfoHTTPClient(userInfoResponse, expectedAccessToken),
			}

			pubkeyList, err := ver.AuthorizedKeysCommand(context.Background(), userArg, typeArg, certB64Arg, mockExtraArgs)

			if tt.errorString != "" {
				require.ErrorContains(t, err, tt.errorString)
				require.Empty(t, pubkeyList)
			} else {
				require.NoError(t, err)

				expectedPubkeyList := tt.expectedLine
				if expectedPubkeyList == "" {
					expectedPubkeyList = defaultExpectedLine
				}
				require.Contains(t, pubkeyList, expectedPubkeyList)

				// The output must never contain characters that could alter how
				// sshd parses the authorized_keys line beyond the base64 pubkey.
				require.NotContains(t, pubkeyList, "\n")
			}
		})

	}
}

func TestEnvFromConfig(t *testing.T) {
	// Do not run this test in parallel with other tests as it modifies environment variables

	configContent := `---
env_vars:
  OPKSSH_TEST_EXAMPLE_VAR1: ABC
  OPKSSH_TEST_EXAMPLE_VAR2: DEF
`

	tests := []struct {
		name        string
		configFile  map[string]string
		permission  fs.FileMode
		Content     string
		owner       string
		group       string
		errorString string
	}{
		{
			name:        "Happy Path",
			configFile:  map[string]string{"server_config.yml": configContent},
			permission:  0640,
			owner:       "root",
			group:       "opksshuser",
			errorString: "",
		},
		{
			name:        "Missing config",
			configFile:  map[string]string{"wrong-filename.yml": configContent},
			permission:  0640,
			owner:       "root",
			group:       "opksshuser",
			errorString: "file does not exist",
		},
		{
			name:        "Corrupted file",
			configFile:  map[string]string{"server_config.yml": `;;;corrupted`},
			permission:  0640,
			owner:       "root",
			group:       "opksshuser",
			errorString: "failed to parse config file",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Unset the environment variables after the test is done to avoid side effects
			defer func() {
				for _, v := range os.Environ() {
					if strings.HasPrefix(v, "OPKSSH_TEST_EXAMPLE_VAR") {
						parts := strings.SplitN(v, "=", 2)
						os.Unsetenv(parts[0])
					}
				}
			}()

			mockFs := afero.NewMemMapFs()
			tempDir, _ := afero.TempDir(mockFs, "opk", "config")
			for name, content := range tt.configFile {
				err := afero.WriteFile(mockFs, filepath.Join(tempDir, name), []byte(content), tt.permission)
				require.NoError(t, err)
			}

			ver := VerifyCmd{
				Fs:            mockFs,
				ConfigPathArg: filepath.Join(tempDir, "server_config.yml"),
				filePermChecker: files.PermsChecker{
					Fs: mockFs,
					CmdRunner: func(name string, arg ...string) ([]byte, error) {
						return []byte(tt.owner + " " + tt.group), nil
					},
				},
			}
			_, err := ver.ReadFromServerConfig()

			if tt.errorString != "" {
				require.ErrorContains(t, err, tt.errorString)
			} else {
				require.NoError(t, err)
				require.Equal(t, "ABC", os.Getenv("OPKSSH_TEST_EXAMPLE_VAR1"))
				require.Equal(t, "DEF", os.Getenv("OPKSSH_TEST_EXAMPLE_VAR2"))
			}
		})
	}

}

func TestErrorOnUnsafePrincipal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		principals  []string
		errorString string
	}{
		{
			name:       "Happy Path (single principal)",
			principals: []string{"alice"},
		},
		{
			name:       "Happy Path (multiple principals)",
			principals: []string{"guest", "dev"},
		},
		{
			name:       "Happy Path (opkssh-wildcard sentinel)",
			principals: []string{"opkssh-wildcard"},
		},
		{
			name:       "Happy Path (empty principal list means no principals option)",
			principals: []string{},
		},
		{
			name:       "Happy Path (nil principal list)",
			principals: nil,
		},
		{
			name:       "Happy Path (leading underscore, Debian/macOS system accounts)",
			principals: []string{"_apt", "_www"},
		},
		{
			name:       "Happy Path (allowed interior special chars)",
			principals: []string{"alice.smith_01", "bob+test@example.com", "web-admin"},
		},
		{
			name:       "Happy Path (trailing $, Samba machine account)",
			principals: []string{"WORKSTATION1$"},
		},
		{
			name:       "Happy Path (max length 128 chars without trailing $)",
			principals: []string{"a" + strings.Repeat("b", 127)},
		},
		{
			name:       "Happy Path (max length 129 chars with trailing $)",
			principals: []string{"a" + strings.Repeat("b", 127) + "$"},
		},
		{
			name:        "Rejects double quote (escapes principals= option)",
			principals:  []string{`alice",command="/bin/sh`},
			errorString: "invalid principal",
		},
		{
			name:        "Rejects newline (injects a second authorized_keys line)",
			principals:  []string{"alice\nssh-ed25519 AAAA attacker@evil"},
			errorString: "invalid principal",
		},
		{
			name:        "Rejects carriage return",
			principals:  []string{"alice\rroot"},
			errorString: "invalid principal",
		},
		{
			name:        "Rejects comma (splits into extra principal)",
			principals:  []string{"alice,root"},
			errorString: "invalid principal",
		},
		{
			name:        "Rejects backslash (escapes closing quote)",
			principals:  []string{`alice\`},
			errorString: "invalid principal",
		},
		{
			name:        "Rejects space",
			principals:  []string{"alice root"},
			errorString: "invalid principal",
		},
		{
			name:        "Rejects tab",
			principals:  []string{"alice\troot"},
			errorString: "invalid principal",
		},
		{
			name:        "Rejects asterisk (pattern wildcard)",
			principals:  []string{"gu*st"},
			errorString: "invalid principal",
		},
		{
			name:        "Rejects question mark (pattern wildcard)",
			principals:  []string{"gues?"},
			errorString: "invalid principal",
		},
		{
			name:        "Rejects leading bang (pattern negation)",
			principals:  []string{"!guest"},
			errorString: "invalid principal",
		},
		{
			name:        "Rejects empty string principal",
			principals:  []string{""},
			errorString: "invalid principal",
		},
		{
			name:        "Rejects leading dash (argument injection hazard)",
			principals:  []string{"-alice"},
			errorString: "invalid principal",
		},
		{
			name:        "Rejects leading dot",
			principals:  []string{".hidden"},
			errorString: "invalid principal",
		},
		{
			name:        "Rejects dot (path hazard)",
			principals:  []string{"."},
			errorString: "invalid principal",
		},
		{
			name:        "Rejects dotdot (path traversal hazard)",
			principals:  []string{".."},
			errorString: "invalid principal",
		},
		{
			name:        "Rejects bare dollar sign",
			principals:  []string{"$"},
			errorString: "invalid principal",
		},
		{
			name:        "Rejects interior dollar sign",
			principals:  []string{"a$b"},
			errorString: "invalid principal",
		},
		{
			name:        "Rejects double trailing dollar sign",
			principals:  []string{"a$$"},
			errorString: "invalid principal",
		},
		{
			name:        "Rejects non-ASCII characters",
			principals:  []string{"aliçe"},
			errorString: "invalid principal",
		},
		{
			name:        "Rejects one bad principal among valid ones",
			principals:  []string{"guest", "dev", `x"`},
			errorString: "invalid principal",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := errorOnUnsafePrincipal(tt.principals)

			if tt.errorString != "" {
				require.ErrorContains(t, err, tt.errorString)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
