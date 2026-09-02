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
	"context"
	"crypto"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ed25519"

	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/jose"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/util"
	"github.com/openpubkey/opkssh/commands/config"
	"github.com/openpubkey/opkssh/sshcert"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
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

func Mocks(t *testing.T, keyType KeyType, extraClaims ...map[string]any) (*pktoken.PKToken, crypto.Signer, providers.OpenIdProvider) {
	var err error
	var alg jose.KeyAlgorithm
	var signer crypto.Signer

	switch keyType {
	case ECDSA:
		alg = jose.ES256
		signer, err = util.GenKeyPair(alg)
	case ED25519:
		alg = jose.EdDSA
		_, signer, err = ed25519.GenerateKey(rand.Reader)
	}
	require.NoError(t, err)

	// LoginCmd.AddKeyToAgent keeps a login off any agent by default; clearing
	// SSH_AUTH_SOCK additionally covers a test that calls addCertToAgent
	// directly. A test that needs an agent points SSH_AUTH_SOCK at its own
	// test agent after calling Mocks.
	t.Setenv("SSH_AUTH_SOCK", "")

	providerOpts := providers.DefaultMockProviderOpts()
	op, _, idtTemplate, err := providers.NewMockProvider(providerOpts)
	require.NoError(t, err)

	// Default: include email claim
	if len(extraClaims) > 0 {
		idtTemplate.ExtraClaims = extraClaims[0]
	} else {
		mockEmail := "arthur.aardvark@example.com"
		idtTemplate.ExtraClaims = map[string]any{
			"email": mockEmail,
		}
	}

	client, err := client.New(op, client.WithSigner(signer, alg))
	require.NoError(t, err)

	pkt, err := client.Auth(context.Background())
	require.NoError(t, err)
	return pkt, signer, op
}

func TestLoginCmd(t *testing.T) {
	logDir := "./logs"
	logPath := filepath.Join(logDir, "opkssh.log")

	defaultConfig, err := config.NewClientConfig(config.DefaultClientConfig)
	require.NoError(t, err, "Failed to get default client config")

	_, _, mockOp := Mocks(t, ECDSA)
	configWithAccessToken := &config.ClientConfig{
		Providers: []config.ProviderConfig{
			{
				AliasList:       []string{"mockOp"},
				Issuer:          mockOp.Issuer(),
				SendAccessToken: true,
			},
		},
		DefaultProvider: "mockOp",
	}

	tests := []struct {
		name            string
		envVars         map[string]string
		loginCmd        LoginCmd
		ClientConfig    *config.ClientConfig
		wantAccessToken bool
		wantError       bool
		errorString     string
	}{
		{
			name:    "Good path with no vars",
			envVars: map[string]string{},
			loginCmd: LoginCmd{
				Verbosity:       2,
				PrintIdTokenArg: true,
				LogDirArg:       logDir,
				Config:          defaultConfig,
			},
			wantError: false,
		},
		{
			name:    "Good path (load config)",
			envVars: map[string]string{},
			loginCmd: LoginCmd{
				Verbosity:       2,
				PrintIdTokenArg: true,
				LogDirArg:       logDir,
			},
			wantError: false,
		},
		{
			name:    "Good path PrintKey",
			envVars: map[string]string{},
			loginCmd: LoginCmd{
				Verbosity:   0,
				PrintKeyArg: true,
				LogDirArg:   logDir,
			},
			wantError: false,
		},
		{
			name:    "Good path PrincipalsArg set to nil",
			envVars: map[string]string{},
			loginCmd: LoginCmd{
				Verbosity:     0,
				PrintKeyArg:   true,
				LogDirArg:     logDir,
				PrincipalsArg: nil,
			},
			wantError: false,
		},
		{
			name:    "Good path PrincipalsArg set to empty",
			envVars: map[string]string{},
			loginCmd: LoginCmd{
				Verbosity:     0,
				PrintKeyArg:   true,
				LogDirArg:     logDir,
				PrincipalsArg: []string{},
			},
			wantError: false,
		},
		{
			name:    "Good path PrincipalsArg set to specific principals",
			envVars: map[string]string{},
			loginCmd: LoginCmd{
				Verbosity:     0,
				PrintKeyArg:   true,
				LogDirArg:     logDir,
				PrincipalsArg: []string{"alice", "bob", "root"},
			},
			wantError: false,
		},
		{
			name:    "Good path InspectCert",
			envVars: map[string]string{},
			loginCmd: LoginCmd{
				Verbosity:      0,
				InspectCertArg: true,
				LogDirArg:      logDir,
			},
			wantError: false,
		},
		{
			name:    "Good path with SendAccessToken set in arg and config",
			envVars: map[string]string{},
			loginCmd: LoginCmd{
				Verbosity:          2,
				LogDirArg:          logDir,
				Config:             configWithAccessToken,
				SendAccessTokenArg: true,
			},
			wantAccessToken: true,
			wantError:       false,
		},
		{
			name:    "Good path with SendAccessToken set in config but not in arg",
			envVars: map[string]string{},
			loginCmd: LoginCmd{
				Verbosity:          2,
				LogDirArg:          logDir,
				Config:             configWithAccessToken,
				SendAccessTokenArg: false,
			},
			wantAccessToken: true,
			wantError:       false,
		},
		{
			name:    "Good path with SendAccessToken Arg (issuer not found in config)",
			envVars: map[string]string{},
			loginCmd: LoginCmd{
				Verbosity:          2,
				LogDirArg:          logDir,
				Config:             defaultConfig,
				SendAccessTokenArg: true,
			},
			wantAccessToken: true,
			wantError:       false,
		},
	}
	keyTypes := [...]KeyType{ECDSA, ED25519}

	for _, tt := range tests {
		for _, keyType := range keyTypes {
			t.Run(fmt.Sprintf("%s %s", tt.name, keyType.String()), func(t *testing.T) {
				for k, v := range tt.envVars {
					err := os.Setenv(k, v)
					require.NoError(t, err, "Failed to set env var")
					defer func(key string) {
						_ = os.Unsetenv(key)
					}(k)
				}

				_, _, mockOp := Mocks(t, keyType)
				mockFs := afero.NewMemMapFs()

				tt.loginCmd.overrideProvider = &mockOp
				tt.loginCmd.Fs = mockFs

				// Allows us to capture non-logged CLI output
				cliOutputBuffer := &bytes.Buffer{}
				tt.loginCmd.OutWriter = cliOutputBuffer

				err = tt.loginCmd.Run(context.Background())
				if tt.wantError {
					require.Error(t, err, "Expected error but got none")
					if tt.errorString != "" {
						require.ErrorContains(t, err, tt.errorString, "Got a wrong error message")
					}
				} else {
					require.NoError(t, err, "Unexpected error")

					var pubKeyBytes []byte

					if tt.loginCmd.PrintKeyArg {
						got := cliOutputBuffer.String()
						gotLines := strings.Split(strings.TrimSpace(got), "\n")
						require.GreaterOrEqual(t, len(gotLines), 2, "expected at least 2 lines in output")
						require.Contains(t, gotLines[0], "cert-v01@openssh.com AAAA")
						require.Contains(t, gotLines[1], "-----BEGIN OPENSSH PRIVATE KEY-----")
						pubKeyBytes = []byte(gotLines[0])
					} else if tt.loginCmd.InspectCertArg {
						got := cliOutputBuffer.String()
						require.Contains(t, got, "--- SSH Certificate Information ---")
						require.Contains(t, got, "--- PKToken Structure ---")

						homePath, err := os.UserHomeDir()
						require.NoError(t, err)
						// KeyTypeArg defaults to ECDSA so keys are written to id_ecdsa path
						sshPubPath := filepath.Join(homePath, ".ssh", "id_ecdsa-cert.pub")
						pubKeyBytes, err = afero.ReadFile(mockFs, sshPubPath)
						require.NoError(t, err)
					} else {
						homePath, err := os.UserHomeDir()
						require.NoError(t, err)

						sshPath := filepath.Join(homePath, ".ssh", "id_ecdsa")
						secKeyBytes, err := afero.ReadFile(mockFs, sshPath)
						require.NoError(t, err)
						require.NotNil(t, secKeyBytes)
						require.Contains(t, string(secKeyBytes), "-----BEGIN OPENSSH PRIVATE KEY-----")

						logBytes, err := afero.ReadFile(mockFs, logPath)
						require.NoError(t, err)
						require.NotNil(t, logBytes)
						require.Contains(t, string(logBytes), "running login command with args:")

						sshPubPath := filepath.Join(homePath, ".ssh", "id_ecdsa-cert.pub")
						pubKeyBytes, err = afero.ReadFile(mockFs, sshPubPath)
						require.NoError(t, err)
					}
					certSmug, err := sshcert.NewFromAuthorizedKey("fake-cert-type", string(pubKeyBytes))
					require.NoError(t, err)

					if tt.loginCmd.PrincipalsArg == nil {
						// We use the wildcard principal when PrincipalsArg is nil
						require.Equal(t, []string{"opkssh-wildcard"}, certSmug.SshCert.ValidPrincipals)
					} else if len(tt.loginCmd.PrincipalsArg) == 0 {
						// A list of length 0 gets deserialized as nil in an sshCert
						require.Nil(t, certSmug.SshCert.ValidPrincipals)
					} else {
						require.Equal(t, tt.loginCmd.PrincipalsArg, certSmug.SshCert.ValidPrincipals)
					}

					accToken := certSmug.GetAccessToken()
					if tt.wantAccessToken {
						require.NotEmpty(t, accToken, "expected access token to be set in SSH cert")
					} else {
						require.Empty(t, accToken, "expected access token to not be set in SSH cert")
					}
				}
			})
		}
	}
}

func TestDetermineProvider(t *testing.T) {
	tests := []struct {
		name              string
		envVars           map[string]string
		providerArg       string
		providerAlias     string
		remoteRedirectURI string
		wantIssuer        string
		wantChooser       string
		wantError         bool
		errorString       string
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
			wantChooser:   `[{"OutputWriter":null,"ErrorWriter":null,"ClientSecret":"","Scopes":["openid profile email"],"PromptType":"consent","AccessType":"offline","RedirectURIs":["http://localhost:3000/login-callback","http://localhost:10001/login-callback","http://localhost:11110/login-callback"],"RemoteRedirectURI":"","GQSign":false,"DeviceFlow":false,"OpenBrowser":false,"HttpClient":null,"IssuedAtOffset":60000000000,"CallbackHTML":"You may now close this window","ExtraURLParamOpts":{}}]`,
		},
		{
			name:          "Good path with env vars many providers and no default",
			envVars:       map[string]string{"OPKSSH_DEFAULT": "", "OPKSSH_PROVIDERS": allProvidersStr},
			providerArg:   "",
			providerAlias: "",
			wantIssuer:    "",
			wantError:     false,
			wantChooser:   `[{"OutputWriter":null,"ErrorWriter":null,"ClientSecret":"","Scopes":["openid profile email"],"PromptType":"consent","AccessType":"offline","RedirectURIs":["http://localhost:3000/login-callback","http://localhost:10001/login-callback","http://localhost:11110/login-callback"],"RemoteRedirectURI":"","GQSign":false,"DeviceFlow":false,"OpenBrowser":false,"HttpClient":null,"IssuedAtOffset":60000000000,"CallbackHTML":"You may now close this window","ExtraURLParamOpts":{}},{"OutputWriter":null,"ErrorWriter":null,"ClientSecret":"","Scopes":["openid profile email"],"PromptType":"consent","AccessType":"offline","RedirectURIs":["http://localhost:3000/login-callback","http://localhost:10001/login-callback","http://localhost:11110/login-callback"],"RemoteRedirectURI":"","GQSign":false,"DeviceFlow":false,"OpenBrowser":false,"HttpClient":null,"IssuedAtOffset":60000000000,"CallbackHTML":"You may now close this window","ExtraURLParamOpts":{}},{"OutputWriter":null,"ErrorWriter":null,"ClientSecret":"","Scopes":["openid profile email"],"PromptType":"consent","AccessType":"offline","RedirectURIs":["http://localhost:3000/login-callback","http://localhost:10001/login-callback","http://localhost:11110/login-callback"],"RemoteRedirectURI":"","GQSign":false,"DeviceFlow":false,"OpenBrowser":false,"HttpClient":null,"IssuedAtOffset":60000000000,"CallbackHTML":"You may now close this window","ExtraURLParamOpts":{}}]`,
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
		{
			name:              "Good path remoteRedirectURI set (no default)",
			envVars:           map[string]string{"OPKSSH_DEFAULT": "", "OPKSSH_PROVIDERS": allProvidersStr},
			providerArg:       "",
			providerAlias:     "",
			remoteRedirectURI: "https://example.com/login_callback",
			wantChooser:       `[{"OutputWriter":null,"ErrorWriter":null,"ClientSecret":"","Scopes":["openid profile email"],"PromptType":"consent","AccessType":"offline","RedirectURIs":["http://localhost:3000/login-callback","http://localhost:10001/login-callback","http://localhost:11110/login-callback"],"RemoteRedirectURI":"https://example.com/login_callback","GQSign":false,"DeviceFlow":false,"OpenBrowser":false,"HttpClient":null,"IssuedAtOffset":60000000000,"CallbackHTML":"You may now close this window","ExtraURLParamOpts":{}},{"OutputWriter":null,"ErrorWriter":null,"ClientSecret":"","Scopes":["openid profile email"],"PromptType":"consent","AccessType":"offline","RedirectURIs":["http://localhost:3000/login-callback","http://localhost:10001/login-callback","http://localhost:11110/login-callback"],"RemoteRedirectURI":"https://example.com/login_callback","GQSign":false,"DeviceFlow":false,"OpenBrowser":false,"HttpClient":null,"IssuedAtOffset":60000000000,"CallbackHTML":"You may now close this window","ExtraURLParamOpts":{}},{"OutputWriter":null,"ErrorWriter":null,"ClientSecret":"","Scopes":["openid profile email"],"PromptType":"consent","AccessType":"offline","RedirectURIs":["http://localhost:3000/login-callback","http://localhost:10001/login-callback","http://localhost:11110/login-callback"],"RemoteRedirectURI":"https://example.com/login_callback","GQSign":false,"DeviceFlow":false,"OpenBrowser":false,"HttpClient":null,"IssuedAtOffset":60000000000,"CallbackHTML":"You may now close this window","ExtraURLParamOpts":{}}]`,
			wantError:         false,
		},
		{
			name:              "Good path remoteRedirectURI set (with default)",
			envVars:           map[string]string{"OPKSSH_DEFAULT": providerAlias3, "OPKSSH_PROVIDERS": allProvidersStr},
			providerArg:       "",
			providerAlias:     "",
			remoteRedirectURI: "https://example.com/login_callback",
			wantIssuer:        providerIssuer3,
			wantError:         false,
		},
		{
			name:              "Good path remoteRedirectURI set (when provider arg specified)",
			envVars:           map[string]string{"OPKSSH_DEFAULT": providerAlias3, "OPKSSH_PROVIDERS": allProvidersStr},
			providerArg:       providerArg2,
			providerAlias:     "",
			remoteRedirectURI: "https://example.com/login_callback",
			wantIssuer:        providerIssuer2,
			wantError:         false,
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

			defaultConfig, err := config.NewClientConfig(config.DefaultClientConfig)
			require.NoError(t, err, "Failed to get default client config")

			loginCmd := LoginCmd{
				DisableBrowserOpenArg: true,
				ProviderArg:           tt.providerArg,
				ProviderAliasArg:      tt.providerAlias,
				PrintIdTokenArg:       true,
				RemoteRedirectURI:     tt.remoteRedirectURI,
				Config:                defaultConfig,
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
				require.False(t, provider != nil && chooser != nil, "Provider or chooser should never both be non-nil")

				if tt.wantIssuer != "" {
					require.NotNil(t, provider)
				}

				if tt.wantChooser != "" {
					require.NotNil(t, chooser)
				}

				if provider != nil {
					require.Equal(t, provider.Issuer(), tt.wantIssuer)

					if tt.remoteRedirectURI != "" {
						// This only covers the case where a single provider is selected.
						// We handle the chooser case by matching against the expected JSON.
						unwrappedOp, ok := provider.(*providers.StandardOp)
						require.True(t, ok, "Expected provider to be of type StandardOp")
						require.Equal(t, tt.remoteRedirectURI, unwrappedOp.RemoteRedirectURI)
					}
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

func TestNewLogin(t *testing.T) {
	autoRefresh := false
	configPathArg := filepath.Join("..", "default-client-config.yml")
	createConfig := false
	configureArg := false
	logDir := "./testdata"
	sendAccessTokenArg := false
	disableBrowserOpenArg := true
	printIdTokenArg := false
	providerArg := ""
	keyPathArg := ""
	providerAlias := ""
	keyAsOutputArg := false
	keyTypeArg := ECDSA
	remoteRedirectURIArg := ""
	var principalsDesired []string = nil
	agentLifetimeArg := "12h"

	loginCmd := NewLogin(autoRefresh, configPathArg, createConfig, configureArg, logDir,
		sendAccessTokenArg, disableBrowserOpenArg, printIdTokenArg, providerArg, keyAsOutputArg, keyPathArg, providerAlias, keyTypeArg, remoteRedirectURIArg, false, principalsDesired, agentLifetimeArg)
	require.NotNil(t, loginCmd)
	require.Equal(t, "12h", loginCmd.AgentLifetimeArg)
}

func TestResolveAgentLifetimeSecs(t *testing.T) {
	tests := []struct {
		name     string
		cmd      LoginCmd
		expected uint32
		errMsg   string
	}{
		{
			name:     "default is 24h when nothing is configured",
			cmd:      LoginCmd{},
			expected: 86400,
		},
		{
			name:     "--lifetime flag as duration",
			cmd:      LoginCmd{AgentLifetimeArg: "12h"},
			expected: 12 * 3600,
		},
		{
			name:     "--lifetime flag as raw seconds",
			cmd:      LoginCmd{AgentLifetimeArg: "28800"},
			expected: 28800,
		},
		{
			name:     "agent_lifetime from client config",
			cmd:      LoginCmd{Config: &config.ClientConfig{AgentLifetime: "8h"}},
			expected: 8 * 3600,
		},
		{
			name:     "--lifetime flag overrides client config",
			cmd:      LoginCmd{AgentLifetimeArg: "2h", Config: &config.ClientConfig{AgentLifetime: "8h"}},
			expected: 2 * 3600,
		},
		{
			name:   "invalid flag value is an error",
			cmd:    LoginCmd{AgentLifetimeArg: "tomorrow"},
			errMsg: "invalid --lifetime value",
		},
		{
			name:   "zero flag value is an error",
			cmd:    LoginCmd{AgentLifetimeArg: "0"},
			errMsg: "must be at least 1 second",
		},
		{
			name:   "negative flag value is an error",
			cmd:    LoginCmd{AgentLifetimeArg: "-5m"},
			errMsg: "must be at least 1 second",
		},
		{
			name:   "sub-second flag value is an error",
			cmd:    LoginCmd{AgentLifetimeArg: "500ms"},
			errMsg: "must be at least 1 second",
		},
		{
			// This value wraps int64 nanoseconds if multiplied without a
			// bound check.
			name:   "overflowing raw seconds value is an error",
			cmd:    LoginCmd{AgentLifetimeArg: "18446744074"},
			errMsg: "out of range",
		},
		{
			name:   "duration exceeding uint32 seconds is an error",
			cmd:    LoginCmd{AgentLifetimeArg: "1193047h"},
			errMsg: "too large",
		},
		{
			name:   "whitespace-only flag value is an error",
			cmd:    LoginCmd{AgentLifetimeArg: "   "},
			errMsg: "empty duration",
		},
		{
			name:   "invalid config value is an error",
			cmd:    LoginCmd{Config: &config.ClientConfig{AgentLifetime: "not-a-duration"}},
			errMsg: "invalid agent_lifetime in client config",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secs, err := tt.cmd.resolveAgentLifetimeSecs()
			if tt.errMsg != "" {
				require.ErrorContains(t, err, tt.errMsg)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expected, secs)
		})
	}
}

// recordingAgent wraps an in-memory ssh-agent and records the keys added to
// it, because agent.Keyring does not expose constraints like LifetimeSecs
// back through List.
type recordingAgent struct {
	agent.Agent
	mu      sync.Mutex
	added   []agent.AddedKey
	removed []ssh.PublicKey
	// addErr makes the agent refuse every key, so that a test can reach the
	// branch addCertToAgent takes when the agent rejects the certificate.
	addErr error
}

func (r *recordingAgent) Add(key agent.AddedKey) error {
	if r.addErr != nil {
		return r.addErr
	}
	r.mu.Lock()
	r.added = append(r.added, key)
	r.mu.Unlock()
	return r.Agent.Add(key)
}

func (r *recordingAgent) Remove(key ssh.PublicKey) error {
	r.mu.Lock()
	r.removed = append(r.removed, key)
	r.mu.Unlock()
	return r.Agent.Remove(key)
}

func (r *recordingAgent) addCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.added)
}

// startTestAgent serves an in-process ssh-agent over a unix socket for the
// duration of the test and points SSH_AUTH_SOCK at it.
func startTestAgent(t *testing.T, a agent.Agent) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("test agent listens on a unix domain socket")
	}
	sockPath := filepath.Join(t.TempDir(), "agent.sock")
	listener, err := net.Listen("unix", sockPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	// addCertToAgent dials once per certificate it loads, so a login that
	// refreshes opens more than one connection over the test's lifetime.
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { _ = agent.ServeAgent(a, conn) }()
		}
	}()
	t.Setenv("SSH_AUTH_SOCK", sockPath)
	return sockPath
}

func TestAddCertToAgent(t *testing.T) {
	// Both key types opkssh can mint have to survive the agent protocol's own
	// marshalling of the private key, which accepts only certain concrete
	// types.
	for _, keyType := range []KeyType{ECDSA, ED25519} {
		t.Run(keyType.String(), func(t *testing.T) {
			pkt, signer, _ := Mocks(t, keyType)
			certBytes, _, err := createSSHCert(pkt, signer, []string{"test"})
			require.NoError(t, err)

			mockAgent := &recordingAgent{Agent: agent.NewKeyring()}
			startTestAgent(t, mockAgent)

			out := &bytes.Buffer{}
			l := &LoginCmd{AgentLifetimeArg: "2h", OutWriter: out}
			l.addCertToAgent(certBytes, signer)
			require.Contains(t, out.String(), "Certificate added to ssh-agent")

			mockAgent.mu.Lock()
			defer mockAgent.mu.Unlock()
			require.Len(t, mockAgent.added, 1)
			added := mockAgent.added[0]
			require.NotNil(t, added.Certificate)
			require.Equal(t, uint32(2*3600), added.LifetimeSecs)
			require.Equal(t, "opkssh", added.Comment)
		})
	}
}

// TestAddCertToAgentWarnings covers the paths where addCertToAgent gives up.
// Authentication has already succeeded by the time it runs, so each failure to
// reach the agent leaves a warning behind rather than failing the login. The
// one path with no case here is the I/O deadline, which needs a connection
// whose SetDeadline fails and so cannot be reached through SSH_AUTH_SOCK.
func TestAddCertToAgentWarnings(t *testing.T) {
	validCert := func(t *testing.T, pkt *pktoken.PKToken, signer crypto.Signer) []byte {
		certBytes, _, err := createSSHCert(pkt, signer, []string{"test"})
		require.NoError(t, err)
		return certBytes
	}

	tests := []struct {
		name        string
		lifetimeArg string
		// setup points SSH_AUTH_SOCK at whatever the case needs and returns
		// the bytes handed to addCertToAgent.
		setup func(t *testing.T, pkt *pktoken.PKToken, signer crypto.Signer) []byte
		// wantWarning is empty for the case that returns without printing.
		wantWarning string
	}{
		{
			name: "no agent in the environment",
			setup: func(t *testing.T, pkt *pktoken.PKToken, signer crypto.Signer) []byte {
				t.Setenv("SSH_AUTH_SOCK", "")
				return validCert(t, pkt, signer)
			},
		},
		{
			name:        "lifetime that does not parse",
			lifetimeArg: "not-a-duration",
			setup: func(t *testing.T, pkt *pktoken.PKToken, signer crypto.Signer) []byte {
				startTestAgent(t, agent.NewKeyring())
				return validCert(t, pkt, signer)
			},
			wantWarning: "warning: not adding certificate to ssh-agent",
		},
		{
			name: "certificate that does not parse",
			setup: func(t *testing.T, pkt *pktoken.PKToken, signer crypto.Signer) []byte {
				startTestAgent(t, agent.NewKeyring())
				return []byte("not an authorized key")
			},
			wantWarning: "warning: could not parse generated certificate for ssh-agent",
		},
		{
			name: "public key that is not a certificate",
			setup: func(t *testing.T, pkt *pktoken.PKToken, signer crypto.Signer) []byte {
				startTestAgent(t, agent.NewKeyring())
				pub, err := ssh.NewPublicKey(signer.Public())
				require.NoError(t, err)
				return ssh.MarshalAuthorizedKey(pub)
			},
			wantWarning: "warning: generated key is not a certificate",
		},
		{
			name: "socket nothing is listening on",
			setup: func(t *testing.T, pkt *pktoken.PKToken, signer crypto.Signer) []byte {
				t.Setenv("SSH_AUTH_SOCK", filepath.Join(t.TempDir(), "absent.sock"))
				return validCert(t, pkt, signer)
			},
			wantWarning: "warning: could not connect to ssh-agent",
		},
		{
			name: "agent that refuses the certificate",
			setup: func(t *testing.T, pkt *pktoken.PKToken, signer crypto.Signer) []byte {
				startTestAgent(t, &recordingAgent{Agent: agent.NewKeyring(), addErr: errors.New("refused")})
				return validCert(t, pkt, signer)
			},
			wantWarning: "warning: failed to add certificate to ssh-agent",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt, signer, _ := Mocks(t, ECDSA)
			certBytes := tt.setup(t, pkt, signer)

			out := &bytes.Buffer{}
			l := &LoginCmd{AgentLifetimeArg: tt.lifetimeArg, OutWriter: out}
			l.addCertToAgent(certBytes, signer)

			if tt.wantWarning == "" {
				require.Empty(t, out.String())
				return
			}
			require.Contains(t, out.String(), tt.wantWarning)
			require.NotContains(t, out.String(), "Certificate added to ssh-agent")
		})
	}
}

// TestLoginAddsToAgentOnlyWhenEnabled exercises the gate LoginCmd puts in
// front of the agent. With AddKeyToAgent unset, a full login leaves a
// reachable agent untouched; that default is what keeps a LoginCmd built
// directly, as tests build it, off a developer's real agent.
func TestLoginAddsToAgentOnlyWhenEnabled(t *testing.T) {
	tests := []struct {
		name          string
		addKeyToAgent bool
		wantAdded     int
	}{
		{name: "default leaves a reachable agent untouched", wantAdded: 0},
		{name: "enabled adds the certificate", addKeyToAgent: true, wantAdded: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, mockOp := Mocks(t, ECDSA)

			mockAgent := &recordingAgent{Agent: agent.NewKeyring()}
			startTestAgent(t, mockAgent)

			l := &LoginCmd{
				Fs:            afero.NewMemMapFs(),
				KeyTypeArg:    ECDSA,
				AddKeyToAgent: tt.addKeyToAgent,
				OutWriter:     &bytes.Buffer{},
			}
			require.NoError(t, l.Login(context.Background(), mockOp, false, ""))

			mockAgent.mu.Lock()
			defer mockAgent.mu.Unlock()
			require.Len(t, mockAgent.added, tt.wantAdded)
		})
	}
}

// TestDefaultClientConfigAgentLifetime holds the default client config to
// defaultAgentLifetime. The template leaves agent_lifetime commented out, and
// CreateDefaultClientConfig copies that file verbatim into a user's config, so
// a new user follows the constant instead of a value frozen into the file.
func TestDefaultClientConfigAgentLifetime(t *testing.T) {
	c, err := config.NewClientConfig(config.DefaultClientConfig)
	require.NoError(t, err)
	require.Empty(t, c.AgentLifetime, "default client config must leave agent_lifetime unset")

	l := LoginCmd{Config: c}
	secs, err := l.resolveAgentLifetimeSecs()
	require.NoError(t, err)
	require.Equal(t, uint32(defaultAgentLifetime/time.Second), secs)
}

func TestCreateSSHCert(t *testing.T) {
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

			// Simple smoke test to verify we can parse the cert
			certPubkey, _, _, _, err := ssh.ParseAuthorizedKey([]byte("certType" + " " + string(sshCertBytes)))
			require.NoError(t, err)
			require.NotNil(t, certPubkey)
		})
	}
}

func TestIdentityString(t *testing.T) {
	t.Run("with email claim", func(t *testing.T) {
		pkt, _, _ := Mocks(t, ECDSA)
		idString, err := IdentityString(*pkt)
		require.NoError(t, err)
		expIdString := "Email, sub, issuer, audience: \narthur.aardvark@example.com me https://accounts.example.com test_client_id"
		require.Equal(t, expIdString, idString)
	})

	t.Run("without email claim", func(t *testing.T) {
		// Create a mock without email claim by passing empty ExtraClaims
		pkt, _, _ := Mocks(t, ECDSA, map[string]any{})

		idString, err := IdentityString(*pkt)
		require.NoError(t, err)
		require.Contains(t, idString, "WARNING: Email claim is missing from ID token")
		require.Contains(t, idString, "Policies based on email will not work")
		require.Contains(t, idString, "Sub, issuer, audience:")
		require.Contains(t, idString, "me")                           // subject
		require.Contains(t, idString, "https://accounts.example.com") // issuer
		require.Contains(t, idString, "test_client_id")               // audience
	})
}

func TestPrettyPrintIdToken(t *testing.T) {
	pkt, _, _ := Mocks(t, ECDSA)
	iss, err := pkt.Issuer()
	require.NoError(t, err)

	pktStr, err := PrettyIdToken(*pkt)
	require.NoError(t, err)
	require.NotNil(t, pktStr)
	require.Contains(t, pktStr, iss)
}

// These tests are a regression suite for
// https://github.com/openpubkey/opkssh/issues/524: the --private-key-file (-i)
// argument must always have the highest precedence when opkssh decides where to
// write the generated SSH key and certificate. The precedence decision lives in
// the single helper writeKeysToDestination; the tests below exercise that helper
// directly and through both callers (Login and LoginWithRefresh).

// writeDest identifies where a key/cert pair is expected to land.
type writeDest int

const (
	destIKeyPath      writeDest = iota // the --private-key-file (-i) path
	destOpkSSHDir                      // the ~/.ssh/opkssh identity directory
	destDefaultSSHDir                  // the default ~/.ssh location
)

// fakeKeyPem and fakeCertBytes are opaque by design: the write helpers persist
// these bytes without parsing them, so the tests do not need valid key
// material. If a helper ever starts validating what it writes, prefer feeding
// it real bytes from createSSHCert rather than these placeholders.
var (
	fakeKeyPem    = []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----\n")
	fakeCertBytes = []byte("ssh-ecdsa-cert-v01@openssh.com AAAAfake")
)

// setupOpkSSHDir creates a configured ~/.ssh/opkssh directory (with an empty
// config file) inside fs and returns its path.
func setupOpkSSHDir(t *testing.T, fs afero.Fs) string {
	t.Helper()
	afs := &afero.Afero{Fs: fs}
	home, err := os.UserHomeDir()
	require.NoError(t, err)
	dir := filepath.Join(home, ".ssh", "opkssh")
	require.NoError(t, afs.MkdirAll(dir, 0o700))
	require.NoError(t, afs.WriteFile(filepath.Join(dir, "config"), []byte(""), 0o600))
	return dir
}

// customKeyPath returns a deterministic -i path inside the (mock) home dir.
func customKeyPath(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	require.NoError(t, err)
	return filepath.Join(home, "custom", "mykey")
}

// assertKeyPairAt asserts that both the private key and cert exist at path.
func assertKeyPairAt(t *testing.T, fs afero.Fs, path string) {
	t.Helper()
	_, err := fs.Stat(path)
	require.NoError(t, err, "expected private key at %s", path)
	_, err = fs.Stat(path + "-cert.pub")
	require.NoError(t, err, "expected cert at %s", path)
}

// assertOpkSSHDirUntouched asserts that the opkssh dir contains only its config
// file, i.e. no key material was written there.
func assertOpkSSHDirUntouched(t *testing.T, fs afero.Fs, dir string) {
	t.Helper()
	entries, err := (&afero.Afero{Fs: fs}).ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		require.Equal(t, "config", e.Name(), "unexpected file written to opkssh dir: %s", e.Name())
	}
}

// assertKeyInOpkSSHDir asserts that at least one file besides config was written
// to the opkssh dir.
func assertKeyInOpkSSHDir(t *testing.T, fs afero.Fs, dir string) {
	t.Helper()
	entries, err := (&afero.Afero{Fs: fs}).ReadDir(dir)
	require.NoError(t, err)
	var keyFiles int
	for _, e := range entries {
		if e.Name() != "config" {
			keyFiles++
		}
	}
	require.Greater(t, keyFiles, 0, "expected key files written to opkssh dir")
}

// TestWriteKeysToDestination exercises the shared destination helper directly.
// Both the single-login and the auto-refresh code paths rely on this helper, so
// asserting its precedence and error wrapping here guards both paths. The table
// covers every branch of the helper, including each error wrapper.
func TestWriteKeysToDestination(t *testing.T) {
	pkt, _, _ := Mocks(t, ECDSA)

	tests := []struct {
		name            string
		useIKeyPath     bool // pass a non-empty -i path
		sshConfigured   bool // l.SSHConfigured
		configureOpkDir bool // create a real ~/.ssh/opkssh/config
		readOnly        bool // wrap the fs read-only to force write failures
		wantErrContains string
		wantDest        writeDest
	}{
		{
			name:            "-i wins over configured opkssh dir (#524)",
			useIKeyPath:     true,
			sshConfigured:   true,
			configureOpkDir: true,
			wantDest:        destIKeyPath,
		},
		{
			name:        "-i wins over default location",
			useIKeyPath: true,
			wantDest:    destIKeyPath,
		},
		{
			name:            "opkssh dir used when configured and no -i",
			sshConfigured:   true,
			configureOpkDir: true,
			wantDest:        destOpkSSHDir,
		},
		{
			name:     "default ~/.ssh used when not configured and no -i",
			wantDest: destDefaultSSHDir,
		},
		{
			name:            "-i write failure is wrapped",
			useIKeyPath:     true,
			readOnly:        true,
			wantErrContains: "failed to write SSH keys to filesystem",
		},
		{
			name:            "opkssh dir write failure is wrapped",
			sshConfigured:   true,
			readOnly:        false, // SSHConfigured but no config file -> read fails
			wantErrContains: "failed to write SSH keys to OPK SSH dir",
		},
		{
			name:            "default location write failure is wrapped",
			readOnly:        true,
			wantErrContains: "failed to write SSH keys to filesystem",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var fs = afero.NewMemMapFs()
			var opkDir string
			if tt.configureOpkDir {
				opkDir = setupOpkSSHDir(t, fs)
			}
			if tt.readOnly {
				fs = afero.NewReadOnlyFs(fs)
			}

			seckeyPath := ""
			if tt.useIKeyPath {
				seckeyPath = customKeyPath(t)
			}

			l := &LoginCmd{
				Fs:            fs,
				SSHConfigured: tt.sshConfigured,
				KeyTypeArg:    ECDSA,
				pkt:           pkt,
			}

			err := l.writeKeysToDestination(seckeyPath, fakeKeyPem, fakeCertBytes)

			if tt.wantErrContains != "" {
				require.ErrorContains(t, err, tt.wantErrContains)
				return
			}
			require.NoError(t, err)

			switch tt.wantDest {
			case destIKeyPath:
				assertKeyPairAt(t, fs, seckeyPath)
				if opkDir != "" {
					assertOpkSSHDirUntouched(t, fs, opkDir)
				}
			case destOpkSSHDir:
				assertKeyInOpkSSHDir(t, fs, opkDir)
				home, err := os.UserHomeDir()
				require.NoError(t, err)
				_, err = fs.Stat(filepath.Join(home, ".ssh", "id_ecdsa"))
				require.Error(t, err, "default location must not be used")
			case destDefaultSSHDir:
				home, err := os.UserHomeDir()
				require.NoError(t, err)
				assertKeyPairAt(t, fs, filepath.Join(home, ".ssh", "id_ecdsa"))
			}
		})
	}
}

// TestLoginWritesKeysToDestination drives Login end-to-end and asserts the same
// precedence, covering the login() call site of writeKeysToDestination
// (including its error return). The success side of this call site is also
// covered by TestLoginCmd; the error case here covers the `return nil, err`.
func TestLoginWritesKeysToDestination(t *testing.T) {
	home, err := os.UserHomeDir()
	require.NoError(t, err)

	tests := []struct {
		name            string
		useIKeyPath     bool
		sshConfigured   bool
		configureOpkDir bool
		readOnly        bool
		wantErrContains string
		wantDest        writeDest
	}{
		{
			name:            "-i wins over configured opkssh dir (#524)",
			useIKeyPath:     true,
			sshConfigured:   true,
			configureOpkDir: true,
			wantDest:        destIKeyPath,
		},
		{
			name:          "opkssh dir used when configured and no -i",
			sshConfigured: true, configureOpkDir: true,
			wantDest: destOpkSSHDir,
		},
		{
			name:     "default ~/.ssh used when not configured and no -i",
			wantDest: destDefaultSSHDir,
		},
		{
			name:            "write failure propagates from login()",
			readOnly:        true,
			wantErrContains: "failed to write SSH keys to filesystem",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, mockOp := Mocks(t, ECDSA)

			var fs = afero.NewMemMapFs()
			var opkDir string
			if tt.configureOpkDir {
				opkDir = setupOpkSSHDir(t, fs)
			}
			if tt.readOnly {
				fs = afero.NewReadOnlyFs(fs)
			}

			seckeyPath := ""
			if tt.useIKeyPath {
				seckeyPath = customKeyPath(t)
			}

			l := &LoginCmd{
				Fs:            fs,
				SSHConfigured: tt.sshConfigured,
				KeyTypeArg:    ECDSA,
				KeyPathArg:    seckeyPath,
				OutWriter:     &bytes.Buffer{},
			}

			err := l.Login(context.Background(), mockOp, false, seckeyPath)

			if tt.wantErrContains != "" {
				require.ErrorContains(t, err, tt.wantErrContains)
				return
			}
			require.NoError(t, err)

			switch tt.wantDest {
			case destIKeyPath:
				assertKeyPairAt(t, fs, seckeyPath)
				assertOpkSSHDirUntouched(t, fs, opkDir)
			case destOpkSSHDir:
				assertKeyInOpkSSHDir(t, fs, opkDir)
				_, err = fs.Stat(filepath.Join(home, ".ssh", "id_ecdsa"))
				require.Error(t, err, "default location must not be used")
			case destDefaultSSHDir:
				assertKeyPairAt(t, fs, filepath.Join(home, ".ssh", "id_ecdsa"))
			}
		})
	}
}

// writeCountingFs counts write-opens (O_CREATE|O_WRONLY) to a single target
// path so a test can tell when a file has been (re)written, e.g. once by the
// initial login and again by a refresh iteration.
type writeCountingFs struct {
	afero.Fs
	target string
	mu     sync.Mutex
	writes int
}

func (c *writeCountingFs) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	if name == c.target && flag&os.O_CREATE != 0 && flag&os.O_WRONLY != 0 {
		c.mu.Lock()
		c.writes++
		c.mu.Unlock()
	}
	return c.Fs.OpenFile(name, flag, perm)
}

func (c *writeCountingFs) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writes
}

// TestLoginWithRefreshWritesKeysToDestination covers the LoginWithRefresh call
// site of writeKeysToDestination. LoginWithRefresh writes once during the
// initial login and again on every refresh, so we wait until the -i key has
// been written at least twice: the second write proves the refresh path routed
// through the shared helper. The token is given a short expiry so the first
// refresh fires immediately, and a bounded context guarantees the loop exits.
func TestLoginWithRefreshWritesKeysToDestination(t *testing.T) {
	// Short expiry: LoginWithRefresh waits until ~1 minute before expiry, so a
	// near-term exp makes the first refresh fire right away.
	shortExp := map[string]any{
		"email": "arthur.aardvark@example.com",
		"exp":   time.Now().Add(15 * time.Second).Unix(),
	}
	_, _, mockOp := Mocks(t, ECDSA, shortExp)

	refreshable, ok := mockOp.(providers.RefreshableOpenIdProvider)
	require.True(t, ok, "mock provider must support refresh")

	iPath := customKeyPath(t)
	fs := &writeCountingFs{Fs: afero.NewMemMapFs(), target: iPath}

	l := &LoginCmd{
		Fs:         fs,
		KeyTypeArg: ECDSA,
		KeyPathArg: iPath,
		OutWriter:  &bytes.Buffer{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- l.LoginWithRefresh(ctx, refreshable, false, iPath)
	}()

	// The initial login writes the key once; the first refresh writes it again.
	require.Eventually(t, func() bool { return fs.count() >= 2 }, 5*time.Second, 5*time.Millisecond,
		"expected the refresh loop to re-write the key via writeKeysToDestination")

	// The key/cert must be at the -i path (never the default or opkssh dir).
	assertKeyPairAt(t, fs, iPath)

	cancel()
	select {
	case err := <-errCh:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("LoginWithRefresh did not return after context cancellation")
	}
}

// TestLoginWithRefreshUpdatesAgent covers the refresh path's use of the agent.
// Each refresh mints a new certificate over the same private key, and the agent
// stores a certificate as its own identity, so the refreshed certificate has to
// both reach the agent and displace the one it supersedes. The keyring holding
// exactly one key at the end is what rules out accumulation, which would
// otherwise grow until a server refuses the connection for too many attempts.
func TestLoginWithRefreshUpdatesAgent(t *testing.T) {
	shortExp := map[string]any{
		"email": "arthur.aardvark@example.com",
		"exp":   time.Now().Add(15 * time.Second).Unix(),
	}
	_, _, mockOp := Mocks(t, ECDSA, shortExp)

	refreshable, ok := mockOp.(providers.RefreshableOpenIdProvider)
	require.True(t, ok, "mock provider must support refresh")

	mockAgent := &recordingAgent{Agent: agent.NewKeyring()}
	startTestAgent(t, mockAgent)

	iPath := customKeyPath(t)
	l := &LoginCmd{
		Fs:            afero.NewMemMapFs(),
		KeyTypeArg:    ECDSA,
		KeyPathArg:    iPath,
		AddKeyToAgent: true,
		OutWriter:     &bytes.Buffer{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- l.LoginWithRefresh(ctx, refreshable, false, iPath)
	}()

	// The initial login adds once; the first refresh adds its replacement.
	require.Eventually(t, func() bool { return mockAgent.addCount() >= 2 }, 5*time.Second, 5*time.Millisecond,
		"expected the refresh loop to load the refreshed certificate into the agent")

	// Stop the loop before inspecting: refreshes keep firing, so the agent is
	// only a settled object once LoginWithRefresh has returned.
	cancel()
	select {
	case err := <-errCh:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("LoginWithRefresh did not return after context cancellation")
	}

	mockAgent.mu.Lock()
	defer mockAgent.mu.Unlock()

	// Every certificate but the newest was removed, and each removal names the
	// certificate added just before it.
	require.Len(t, mockAgent.removed, len(mockAgent.added)-1)
	for i, removed := range mockAgent.removed {
		require.Equal(t, mockAgent.added[i].Certificate.Marshal(), removed.Marshal(),
			"removal %d must name the certificate added before it", i)
	}

	keys, err := mockAgent.List()
	require.NoError(t, err)
	require.Len(t, keys, 1, "the agent must hold only the current certificate")
	newest := mockAgent.added[len(mockAgent.added)-1].Certificate
	require.Equal(t, newest.Marshal(), keys[0].Marshal(),
		"the surviving certificate must be the most recently minted one")
}

// includeDirective must match the directive written by configureSSH.
const includeDirective = "Include ~/.ssh/opkssh/config"

// faultyFs wraps an afero.Fs and injects failures into Open (used by ReadFile)
// and OpenFile (used by create/WriteFile) for chosen paths, so tests can drive
// configureSSH's individual error branches without a real read-only filesystem.
type faultyFs struct {
	afero.Fs
	failOpen     func(name string) bool
	failOpenFile func(name string, flag int) bool
}

func (f *faultyFs) Open(name string) (afero.File, error) {
	if f.failOpen != nil && f.failOpen(name) {
		return nil, fmt.Errorf("injected Open failure: %s", name)
	}
	return f.Fs.Open(name)
}

func (f *faultyFs) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	if f.failOpenFile != nil && f.failOpenFile(name, flag) {
		return nil, fmt.Errorf("injected OpenFile failure: %s", name)
	}
	return f.Fs.OpenFile(name, flag, perm)
}

// sshConfigPaths returns the three paths configureSSH operates on, derived from
// the current user's home directory.
func sshConfigPaths(t *testing.T) (sshConfig, opkConfig string) {
	t.Helper()
	home, err := os.UserHomeDir()
	require.NoError(t, err)
	return filepath.Join(home, ".ssh/config"), filepath.Join(home, ".ssh/opkssh/config")
}

func TestConfigureSSH(t *testing.T) {
	sshConfig, opkConfig := sshConfigPaths(t)

	tests := []struct {
		name            string
		setupFs         func(t *testing.T) afero.Fs
		wantErrContains string
		wantContains    string // substring the resulting ~/.ssh/config must contain
		wantExactConfig string // if set, the full resulting ~/.ssh/config content
	}{
		{
			name:         "fresh setup writes directive",
			setupFs:      func(t *testing.T) afero.Fs { return afero.NewMemMapFs() },
			wantContains: includeDirective,
		},
		{
			name: "existing config gets directive prepended",
			setupFs: func(t *testing.T) afero.Fs {
				fs := afero.NewMemMapFs()
				require.NoError(t, (&afero.Afero{Fs: fs}).WriteFile(sshConfig, []byte("Host example\n"), 0o600))
				return fs
			},
			wantExactConfig: includeDirective + "\n\nHost example\n",
		},
		{
			name: "already configured is idempotent",
			setupFs: func(t *testing.T) afero.Fs {
				fs := afero.NewMemMapFs()
				afs := &afero.Afero{Fs: fs}
				// opkssh config already present -> hits the "already configured" branch
				require.NoError(t, afs.WriteFile(opkConfig, []byte(""), 0o600))
				// ssh config already contains the directive -> the write is skipped
				require.NoError(t, afs.WriteFile(sshConfig, []byte(includeDirective+"\n\nHost example\n"), 0o600))
				return fs
			},
			wantExactConfig: includeDirective + "\n\nHost example\n", // unchanged, not duplicated
		},
		{
			name:            "mkdir failure",
			setupFs:         func(t *testing.T) afero.Fs { return afero.NewReadOnlyFs(afero.NewMemMapFs()) },
			wantErrContains: "failed to create opkssh SSH directory",
		},
		{
			name: "opkssh config create failure",
			setupFs: func(t *testing.T) afero.Fs {
				return &faultyFs{
					Fs:           afero.NewMemMapFs(),
					failOpenFile: func(name string, _ int) bool { return name == opkConfig },
				}
			},
			wantErrContains: "failed to create opkssh SSH directory",
		},
		{
			name: "read ssh config failure",
			setupFs: func(t *testing.T) afero.Fs {
				return &faultyFs{
					Fs:       afero.NewMemMapFs(),
					failOpen: func(name string) bool { return name == sshConfig },
				}
			},
			wantErrContains: "failed to read SSH config file",
		},
		{
			name: "write ssh config failure",
			setupFs: func(t *testing.T) afero.Fs {
				return &faultyFs{
					Fs: afero.NewMemMapFs(),
					failOpenFile: func(name string, flag int) bool {
						return name == sshConfig && flag&os.O_WRONLY != 0
					},
				}
			},
			wantErrContains: "failed to write SSH config file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := tt.setupFs(t)
			l := &LoginCmd{Fs: fs}

			err := l.configureSSH()

			if tt.wantErrContains != "" {
				require.ErrorContains(t, err, tt.wantErrContains)
				require.False(t, l.SSHConfigured, "SSHConfigured must stay false on error")
				return
			}

			require.NoError(t, err)
			require.True(t, l.SSHConfigured, "SSHConfigured must be set on success")

			afs := &afero.Afero{Fs: fs}
			exists, err := afs.Exists(opkConfig)
			require.NoError(t, err)
			require.True(t, exists, "opkssh config file should have been created")

			got, err := afs.ReadFile(sshConfig)
			require.NoError(t, err)
			if tt.wantExactConfig != "" {
				require.Equal(t, tt.wantExactConfig, string(got))
			}
			if tt.wantContains != "" {
				require.Contains(t, string(got), tt.wantContains)
			}
		})
	}
}

// TestConfigureSSHHomeDirError covers the os.UserHomeDir() failure branch by
// clearing HOME. This resolution path only applies on non-Windows platforms.
func TestConfigureSSHHomeDirError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("home directory is not resolved via HOME on Windows")
	}
	t.Setenv("HOME", "")

	l := &LoginCmd{Fs: afero.NewMemMapFs()}
	err := l.configureSSH()

	require.ErrorContains(t, err, "failed to get user config dir")
	require.False(t, l.SSHConfigured)
}

func TestDetermineProviderCICDAliasErrors(t *testing.T) {
	defaultConfig, err := config.NewClientConfig(config.DefaultClientConfig)
	require.NoError(t, err)

	forgejoTokenURL := "https://codeberg.org/api/actions/_apis/pipelines/workflows/42/idtoken?placeholder=true"
	githubTokenURL := "https://pipelines.actions.githubusercontent.com/abc/_apis/pipelines/1/runs/2/idtoken?api-version=2.0"

	tests := []struct {
		name            string
		alias           string
		tokenRequestURL string
		errorString     string
	}{
		{
			name:        "forgejo alias outside an Actions environment",
			alias:       "forgejo",
			errorString: "only works inside a Forgejo Actions workflow",
		},
		{
			name:        "codeberg alias outside an Actions environment",
			alias:       "codeberg",
			errorString: "only works inside a Forgejo Actions workflow",
		},
		{
			name:        "github alias outside an Actions environment",
			alias:       "github",
			errorString: "only works inside a GitHub Actions workflow",
		},
		{
			name:            "forgejo alias in a GitHub Actions environment",
			alias:           "forgejo",
			tokenRequestURL: githubTokenURL,
			errorString:     "use `opkssh login github` instead",
		},
		{
			name:            "github alias in a Forgejo Actions environment",
			alias:           "github",
			tokenRequestURL: forgejoTokenURL,
			errorString:     "use `opkssh login forgejo` instead",
		},
		{
			name:        "gitlab-ci alias outside a GitLab CI/CD pipeline",
			alias:       "gitlab-ci",
			errorString: "only works inside a GitLab CI/CD pipeline",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requestToken := ""
			if tt.tokenRequestURL != "" {
				requestToken = "runner-token"
			}
			t.Setenv("OPKSSH_DEFAULT", "")
			t.Setenv("OPKSSH_PROVIDERS", "")
			t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", tt.tokenRequestURL)
			t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", requestToken)
			t.Setenv("GITLAB_CI", "")

			login := LoginCmd{Config: defaultConfig, ProviderAliasArg: tt.alias}
			_, _, err := login.determineProvider()
			require.ErrorContains(t, err, tt.errorString)
		})
	}
}

func TestDetermineProviderGitlabCIEnvironment(t *testing.T) {
	defaultConfig, err := config.NewClientConfig(config.DefaultClientConfig)
	require.NoError(t, err)
	t.Setenv("OPKSSH_DEFAULT", "")
	t.Setenv("OPKSSH_PROVIDERS", "")
	t.Setenv("GITLAB_CI", "true")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")

	// Mirrors the auto-registration Run() does before determineProvider() is
	// called; not calling Run() itself since it has unrelated side effects
	// (SSH config checks, logging setup).
	defaultConfig.Providers = append(defaultConfig.Providers, config.GitlabCiProviderConfig("https://gitlab.com"))

	login := LoginCmd{Config: defaultConfig, ProviderAliasArg: "gitlab-ci"}
	provider, _, err := login.determineProvider()
	require.NoError(t, err)
	require.Equal(t, "https://gitlab.com", provider.Issuer())
}

func TestGitlabCiIssuer(t *testing.T) {
	t.Setenv("CI_SERVER_URL", "")
	require.Equal(t, "https://gitlab.com", gitlabCiIssuer())

	t.Setenv("CI_SERVER_URL", "https://gitlab.example.com")
	require.Equal(t, "https://gitlab.example.com", gitlabCiIssuer())
}

// OPKSSH_PROVIDERS replaces the provider list wholesale, which drops the
// CI/CD provider Run() auto-registers. The error has to say so, otherwise it
// reads as "you are not in a CI/CD environment" while sitting in one.
func TestDetermineProviderCICDAliasDroppedByProvidersEnvVar(t *testing.T) {
	defaultConfig, err := config.NewClientConfig(config.DefaultClientConfig)
	require.NoError(t, err)

	tests := []struct {
		name            string
		alias           string
		tokenRequestURL string
		gitlabCI        string
	}{
		{
			name:            "forgejo",
			alias:           "forgejo",
			tokenRequestURL: "https://codeberg.org/api/actions/_apis/pipelines/workflows/42/idtoken?placeholder=true",
		},
		{
			name:            "github",
			alias:           "github",
			tokenRequestURL: "https://pipelines.actions.githubusercontent.com/abc/_apis/pipelines/1/runs/2/idtoken?api-version=2.0",
		},
		{
			name:     "gitlab-ci",
			alias:    "gitlab-ci",
			gitlabCI: "true",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requestToken := ""
			if tt.tokenRequestURL != "" {
				requestToken = "runner-token"
			}
			t.Setenv("OPKSSH_DEFAULT", "")
			t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", tt.tokenRequestURL)
			t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", requestToken)
			t.Setenv("GITLAB_CI", tt.gitlabCI)
			// An unrelated provider set through the env var, as a workflow
			// pointing opkssh at its own OP would do.
			t.Setenv("OPKSSH_PROVIDERS", "https://op.example.com,client-id,client-secret,openid email")

			// The provider Run() would have auto-registered is present in the
			// config and still unreachable, because the env var wins.
			cfg := *defaultConfig
			cfg.Providers = append(cfg.Providers, config.GitlabCiProviderConfig("https://gitlab.com"))

			login := LoginCmd{Config: &cfg, ProviderAliasArg: tt.alias}
			_, _, err := login.determineProvider()
			require.ErrorContains(t, err, "OPKSSH_PROVIDERS")
		})
	}
}

// The web chooser cannot offer CI/CD providers, so a list containing nothing
// else must fail instead of serving an empty chooser page forever.
func TestDetermineProviderWebChooserWithOnlyCICDProviders(t *testing.T) {
	t.Setenv("OPKSSH_DEFAULT", "")
	t.Setenv("OPKSSH_PROVIDERS", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
	t.Setenv("GITLAB_CI", "")

	cfg := &config.ClientConfig{
		Providers: []config.ProviderConfig{
			config.GitHubProviderConfig(),
			config.ForgejoProviderConfig("https://codeberg.org/api/actions"),
		},
	}
	login := LoginCmd{Config: cfg}
	_, chooser, err := login.determineProvider()
	require.ErrorContains(t, err, "no browser-based providers configured")
	require.Nil(t, chooser)
}
