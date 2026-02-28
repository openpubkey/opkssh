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

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/client"
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

	alg := jwa.ES256
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

	tests := []struct {
		name        string
		accessToken string
		errorString string
		policyFunc  func(userDesired string, pkt *pktoken.PKToken, userInfo string, certB64 string, typArg string, denyList policy.DenyList, extraArgs []string) error
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

			principals := []string{"guest", "dev"}
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

				expectedPubkeyList := "cert-authority ecdsa-sha2-nistp256"
				require.Contains(t, pubkeyList, expectedPubkeyList)
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
			err := ver.ReadFromServerConfig()

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
