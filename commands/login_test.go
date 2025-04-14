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
	"crypto"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/util"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

const providerAlias1 = "op1"
const providerIssuer1 = "https://example.com/tokens-1/"
const providerArg1 = providerIssuer1 + ",client-id1234,,"
const providerStr1 = providerAlias1 + "," + providerArg1

const providerAlias2 = "op2"
const providerIssuer2 = "https://auth.issuer/tokens-2/"
const providerArg2 = providerIssuer2 + ",client-id5678,,"
const providerStr2 = providerAlias2 + "," + providerArg2

const providerAlias3 = "op3"
const providerIssuer3 = "https://openidprovider.openidconnect/tokens-3/"
const providerArg3 = providerIssuer3 + ",client-id91011,,"
const providerStr3 = providerAlias3 + "," + providerArg3

const allProvidersStr = providerStr1 + ";" + providerStr2 + ";" + providerStr3

func Mocks(t *testing.T) (*pktoken.PKToken, crypto.Signer, providers.OpenIdProvider) {
	alg := jwa.ES256
	signer, err := util.GenKeyPair(alg)
	require.NoError(t, err)

	providerOpts := providers.DefaultMockProviderOpts()
	op, _, idtTemplate, err := providers.NewMockProvider(providerOpts)
	require.NoError(t, err)

	mockEmail := "arthur.aardvark@example.com"
	idtTemplate.ExtraClaims = map[string]any{
		"email": mockEmail,
	}

	client, err := client.New(op, client.WithSigner(signer, alg))
	require.NoError(t, err)

	pkt, err := client.Auth(context.Background())
	require.NoError(t, err)
	return pkt, signer, op
}

func ProviderFromString(t *testing.T, providerString string) providers.OpenIdProvider {
	providerConfig3, err := NewProviderConfigFromString(providerStr3, true)
	require.NoError(t, err)
	provider3, err := NewProviderFromConfig(providerConfig3, false)
	require.NoError(t, err)
	return provider3
}

func TestLoginCmd(t *testing.T) {
	_, _, mockOp := Mocks(t)

	mockFs := afero.NewMemMapFs()
	loginCmd := LoginCmd{
		Fs:                    mockFs,
		disableBrowserOpenArg: true,
		overrideProvider:      &mockOp,
	}
	require.NotNil(t, loginCmd)
	err := loginCmd.Run(context.Background())
	require.NoError(t, err)

	homePath, err := os.UserHomeDir()
	require.NoError(t, err)

	sshPath := filepath.Join(homePath, ".ssh", "id_ecdsa")
	secKeyBytes, err := afero.ReadFile(mockFs, sshPath)
	require.NoError(t, err)
	require.NotNil(t, secKeyBytes)
	require.Contains(t, string(secKeyBytes), "-----BEGIN OPENSSH PRIVATE KEY-----")
}

func TestDetermineProvider(t *testing.T) {
	tests := []struct {
		name          string
		envVars       map[string]string
		providerArg   string
		providerAlias string
		wantIssuer    string
		wantChooser   string
		wantError     bool
		errorString   string
	}{
		{
			name:          "Good path with env vars",
			envVars:       map[string]string{"OPKSSH_DEFAULT": providerAlias1, "OPKSSH_PROVIDERS": providerStr1},
			providerArg:   "",
			providerAlias: "",
			wantIssuer:    providerIssuer1,
			wantError:     false,
		},
		{
			name:          "Good path with env vars and provider arg (provider arg takes precedence)",
			envVars:       map[string]string{"OPKSSH_DEFAULT": providerAlias1, "OPKSSH_PROVIDERS": providerStr1},
			providerArg:   providerArg2,
			providerAlias: "",
			wantIssuer:    providerIssuer2,
			wantError:     false,
		},
		{
			name:          "Good path with env vars and no alias",
			envVars:       map[string]string{"OPKSSH_DEFAULT": providerAlias1, "OPKSSH_PROVIDERS": providerStr1},
			providerArg:   "",
			providerAlias: "",
			wantIssuer:    providerIssuer1,
			wantError:     false,
		},
		{
			name:          "Good path with env vars single provider and no default",
			envVars:       map[string]string{"OPKSSH_DEFAULT": "", "OPKSSH_PROVIDERS": providerStr1},
			providerArg:   "",
			providerAlias: "",
			wantIssuer:    "",
			wantError:     false,
			errorString:   "",
			wantChooser:   `[{"Scopes":[""],"RedirectURIs":["http://localhost:3000/login-callback","http://localhost:10001/login-callback","http://localhost:11110/login-callback"],"GQSign":false,"OpenBrowser":false,"HttpClient":null,"IssuedAtOffset":60000000000}]`,
		},
		{
			name:          "Good path with env vars many providers and no default",
			envVars:       map[string]string{"OPKSSH_DEFAULT": "", "OPKSSH_PROVIDERS": allProvidersStr},
			providerArg:   "",
			providerAlias: "",
			wantIssuer:    "",
			wantError:     false,
			wantChooser:   `[{"Scopes":[""],"RedirectURIs":["http://localhost:3000/login-callback","http://localhost:10001/login-callback","http://localhost:11110/login-callback"],"GQSign":false,"OpenBrowser":false,"HttpClient":null,"IssuedAtOffset":60000000000},{"Scopes":[""],"RedirectURIs":["http://localhost:3000/login-callback","http://localhost:10001/login-callback","http://localhost:11110/login-callback"],"GQSign":false,"OpenBrowser":false,"HttpClient":null,"IssuedAtOffset":60000000000},{"Scopes":[""],"RedirectURIs":["http://localhost:3000/login-callback","http://localhost:10001/login-callback","http://localhost:11110/login-callback"],"GQSign":false,"OpenBrowser":false,"HttpClient":null,"IssuedAtOffset":60000000000}]`,
		},
		{
			name:          "Good path with env vars many providers and providerAlias",
			envVars:       map[string]string{"OPKSSH_DEFAULT": "", "OPKSSH_PROVIDERS": allProvidersStr},
			providerArg:   "",
			providerAlias: providerAlias2,
			wantIssuer:    providerIssuer2,
			wantError:     false,
		},
		{
			name:          "Good path with env vars many providers and providerAlias",
			envVars:       map[string]string{"OPKSSH_DEFAULT": providerAlias3, "OPKSSH_PROVIDERS": allProvidersStr},
			providerArg:   "",
			providerAlias: "",
			wantIssuer:    providerIssuer3,
			wantError:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.envVars {
				err := os.Setenv(k, v)
				require.NoError(t, err, "Failed to set env var")
				defer func(key string) {
					_ = os.Unsetenv(key)
				}(k)
			}

			loginCmd := LoginCmd{
				disableBrowserOpenArg: true,
				providerArg:           tt.providerArg,
				providerAlias:         tt.providerAlias,
				printIdTokenArg:       true,
			}

			provider, chooser, err := loginCmd.determineProvider()
			if tt.wantError {
				require.Error(t, err, "Expected error but got none")
				if tt.errorString != "" {
					require.ErrorContains(t, err, tt.errorString, "Got a wrong error message")
				}
			} else {
				require.NoError(t, err, "Unexpected error")
				require.True(t, provider != nil || chooser != nil, "Provider or chooser should never both be nil")
				require.True(t, !(provider != nil && chooser != nil), "Provider or chooser should never both be non-nil")

				if tt.wantIssuer != "" {
					require.NotNil(t, provider)
				}

				if tt.wantChooser != "" {
					require.NotNil(t, chooser)
				}

				if provider != nil {
					require.Equal(t, provider.Issuer(), tt.wantIssuer)
				} else {
					require.NotNil(t, chooser.OpList, "Chooser OpList should not be nil")
					jsonBytes, err := json.Marshal(chooser.OpList)
					require.NoError(t, err)
					require.Equal(t, tt.wantChooser, string(jsonBytes))
				}
			}
		})
	}
}

func TestProviderConfigFromString(t *testing.T) {
	providerConfig3, err := NewProviderConfigFromString(providerStr3, true)
	require.NoError(t, err)
	provider3, err := NewProviderFromConfig(providerConfig3, false)
	require.NoError(t, err)

	require.NotNil(t, provider3)
	require.Equal(t, provider3.Issuer(), providerIssuer3)
}

func TestNewLogin(t *testing.T) {
	autoRefresh := false
	logDir := "./testdata"
	disableBrowserOpenArg := true
	printIdTokenArg := false
	providerArg := ""
	keyPathArg := ""
	providerAlias := ""

	loginCmd := NewLogin(autoRefresh, logDir, disableBrowserOpenArg, printIdTokenArg, providerArg, keyPathArg, providerAlias)
	require.NotNil(t, loginCmd)
}

func TestCreateSSHCert(t *testing.T) {
	pkt, signer, _ := Mocks(t)
	principals := []string{"guest", "dev"}

	sshCertBytes, signKeyBytes, err := createSSHCert(pkt, signer, principals)
	require.NoError(t, err)
	require.NotNil(t, sshCertBytes)
	require.NotNil(t, signKeyBytes)

	// Simple smoke test to verify we can parse the cert
	certPubkey, _, _, _, err := ssh.ParseAuthorizedKey([]byte("certType" + " " + string(sshCertBytes)))
	require.NoError(t, err)
	require.NotNil(t, certPubkey)
}

func TestIdentityString(t *testing.T) {
	pkt, _, _ := Mocks(t)
	idString, err := IdentityString(*pkt)
	require.NoError(t, err)
	expIdString := "Email, sub, issuer, audience: \narthur.aardvark@example.com me https://accounts.example.com test_client_id"
	require.Equal(t, expIdString, idString)
}

func TestPrettyPrintIdToken(t *testing.T) {
	pkt, _, _ := Mocks(t)
	iss, err := pkt.Issuer()
	require.NoError(t, err)

	pktStr, err := PrettyIdToken(*pkt)
	require.NoError(t, err)
	require.NotNil(t, pktStr)
	require.Contains(t, pktStr, iss)
}
