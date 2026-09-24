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
	"path/filepath"
	"strings"
	"testing"

	"github.com/openpubkey/opkssh/commands/config"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

const userClientConfig = `---
# My opkssh config
default_provider: mykeycloak

providers:
  - alias: mykeycloak kc # both aliases work
    issuer: https://keycloak.example.com/realms/opkssh
    client_id: opkssh
    client_secret: old-secret
    scopes: openid email groups
`

func TestClientProviderAdd(t *testing.T) {
	configPath := filepath.Join("home", "alice", ".opk", "config.yml")

	tests := []struct {
		name string
		// existing is the client config before the command, nil if there is none
		existing []byte
		cmd      ClientProviderAddCmd
		// check is called with the client config after a successful command
		check       func(t *testing.T, content string, clientConfig *config.ClientConfig)
		wantOut     string
		errorString string
	}{
		{
			name: "no client config: creates it from the default config",
			cmd:  ClientProviderAddCmd{Alias: "mykeycloak", Issuer: "https://keycloak.example.com/realms/opkssh", ClientID: "opkssh"},
			check: func(t *testing.T, content string, clientConfig *config.ClientConfig) {
				providers, err := clientConfig.GetProvidersMap()
				require.NoError(t, err)
				require.Contains(t, providers, "google", "expected the default providers to be kept")
				require.Equal(t, "opkssh", providers["mykeycloak"].ClientID)
				require.Equal(t, []string{"openid", "profile", "email"}, providers["mykeycloak"].Scopes)
				require.Contains(t, content, "# How long ssh-agent retains the certificate", "expected the default config comments to be kept")
			},
			wantOut: "Added provider mykeycloak (https://keycloak.example.com/realms/opkssh)",
		},
		{
			name:     "replace the default Google client ID with your own",
			existing: config.DefaultClientConfig,
			cmd: ClientProviderAddCmd{Alias: "google", Issuer: "https://accounts.google.com", ClientID: "my-id.apps.googleusercontent.com",
				ClientSecret: "my-secret", Replace: true},
			check: func(t *testing.T, content string, clientConfig *config.ClientConfig) {
				google, ok := clientConfig.GetByIssuer("https://accounts.google.com")
				require.True(t, ok)
				require.Equal(t, []string{"google"}, google.AliasList)
				require.Equal(t, "my-id.apps.googleusercontent.com", google.ClientID)
				require.Equal(t, "my-secret", google.ClientSecret)
				require.Len(t, google.RedirectURIs, 3, "expected the provider settings to be kept")
				require.False(t, config.IsDefaultClientID(google.Issuer, google.ClientID))
				require.Len(t, clientConfig.Providers, 4)

				// Only the client ID and secret change, down to comments and blank lines
				defaultConfig, err := config.NewClientConfig(config.DefaultClientConfig)
				require.NoError(t, err)
				defaultGoogle, ok := defaultConfig.GetByIssuer("https://accounts.google.com")
				require.True(t, ok)
				expected := strings.Replace(string(config.DefaultClientConfig), defaultGoogle.ClientID, "my-id.apps.googleusercontent.com", 1)
				expected = strings.Replace(expected, defaultGoogle.ClientSecret, "my-secret", 1)
				require.Equal(t, expected, content)
			},
			wantOut: "Replaced provider google (https://accounts.google.com)",
		},
		{
			name:     "replace keeps the other aliases of the provider",
			existing: config.DefaultClientConfig,
			cmd: ClientProviderAddCmd{Alias: "microsoft", Issuer: "https://login.microsoftonline.com/my-tenant-id/v2.0",
				ClientID: "my-azure-client-id", Replace: true},
			check: func(t *testing.T, content string, clientConfig *config.ClientConfig) {
				providers, err := clientConfig.GetProvidersMap()
				require.NoError(t, err)
				require.Equal(t, "my-azure-client-id", providers["azure"].ClientID)
				require.Equal(t, "my-azure-client-id", providers["microsoft"].ClientID)
				require.Equal(t, []string{"openid", "profile", "email", "offline_access"}, providers["azure"].Scopes)
			},
		},
		{
			name:     "keeps the comments of your client config",
			existing: []byte(userClientConfig),
			cmd:      ClientProviderAddCmd{Alias: "gitlab", Issuer: "https://gitlab.com", ClientID: "my-gitlab-client-id"},
			check: func(t *testing.T, content string, clientConfig *config.ClientConfig) {
				require.Contains(t, content, "# My opkssh config")
				require.Contains(t, content, "# both aliases work")
				require.Equal(t, "mykeycloak", clientConfig.DefaultProvider)
				providers, err := clientConfig.GetProvidersMap()
				require.NoError(t, err)
				require.Equal(t, "my-gitlab-client-id", providers["gitlab"].ClientID)
				require.Equal(t, "opkssh", providers["kc"].ClientID)
			},
		},
		{
			name:     "keeps the CRLF line endings of your client config",
			existing: []byte(strings.ReplaceAll(userClientConfig, "\n", "\r\n")),
			cmd:      ClientProviderAddCmd{Alias: "gitlab", Issuer: "https://gitlab.com", ClientID: "my-gitlab-client-id"},
			check: func(t *testing.T, content string, clientConfig *config.ClientConfig) {
				require.Equal(t, strings.Count(content, "\n"), strings.Count(content, "\r\n"), "expected only CRLF line endings")
				lf := strings.ReplaceAll(content, "\r\n", "\n")
				require.Contains(t, lf, "---\n# My opkssh config\ndefault_provider: mykeycloak\n\nproviders:\n")
				gitlab, ok := clientConfig.GetByIssuer("https://gitlab.com")
				require.True(t, ok)
				require.Equal(t, "my-gitlab-client-id", gitlab.ClientID)
			},
		},
		{
			name:     "replace without --client-secret removes the old client secret",
			existing: []byte(userClientConfig),
			cmd:      ClientProviderAddCmd{Alias: "kc", Issuer: "https://keycloak.example.com/realms/opkssh", ClientID: "new-client", Replace: true},
			check: func(t *testing.T, content string, clientConfig *config.ClientConfig) {
				kc, ok := clientConfig.GetByIssuer("https://keycloak.example.com/realms/opkssh")
				require.True(t, ok)
				require.Equal(t, "new-client", kc.ClientID)
				require.Empty(t, kc.ClientSecret)
				require.NotContains(t, content, "old-secret")
				require.Equal(t, []string{"openid", "email", "groups"}, kc.Scopes)
			},
		},
		{
			name:     "sets scopes",
			existing: []byte(userClientConfig),
			cmd:      ClientProviderAddCmd{Alias: "gitlab", Issuer: "https://gitlab.com", ClientID: "my-gitlab-client-id", Scopes: "openid email"},
			check: func(t *testing.T, content string, clientConfig *config.ClientConfig) {
				gitlab, ok := clientConfig.GetByIssuer("https://gitlab.com")
				require.True(t, ok)
				require.Equal(t, []string{"openid", "email"}, gitlab.Scopes)
			},
		},
		{
			name:     "empty client config",
			existing: []byte{},
			cmd:      ClientProviderAddCmd{Alias: "gitlab", Issuer: "https://gitlab.com", ClientID: "my-gitlab-client-id"},
			check: func(t *testing.T, content string, clientConfig *config.ClientConfig) {
				require.Len(t, clientConfig.Providers, 1)
			},
		},
		{
			name:        "alias that exists, without --replace",
			existing:    config.DefaultClientConfig,
			cmd:         ClientProviderAddCmd{Alias: "google", Issuer: "https://accounts.google.com", ClientID: "my-id", ClientSecret: "my-secret"},
			errorString: "provider google already exists; use --replace to replace it",
		},
		{
			name:        "issuer used by another provider",
			existing:    config.DefaultClientConfig,
			cmd:         ClientProviderAddCmd{Alias: "mygoogle", Issuer: "https://accounts.google.com", ClientID: "my-id", ClientSecret: "my-secret"},
			errorString: "provider google already uses issuer https://accounts.google.com; to use your client ID with it, run the same command with alias google and --replace",
		},
		{
			name:        "Google without client secret",
			existing:    config.DefaultClientConfig,
			cmd:         ClientProviderAddCmd{Alias: "google", Issuer: "https://accounts.google.com", ClientID: "my-id", Replace: true},
			errorString: "the Google OpenID Provider requires --client-secret",
		},
		{
			name:        "issuer that is not https",
			existing:    config.DefaultClientConfig,
			cmd:         ClientProviderAddCmd{Alias: "local", Issuer: "http://keycloak.example.com", ClientID: "opkssh"},
			errorString: "Expected issuer to start with 'https://'",
		},
		{
			name:        "empty client ID",
			existing:    config.DefaultClientConfig,
			cmd:         ClientProviderAddCmd{Alias: "kc", Issuer: "https://keycloak.example.com", ClientID: ""},
			errorString: "invalid provider client-ID",
		},
		{
			name:        "alias with a space",
			existing:    config.DefaultClientConfig,
			cmd:         ClientProviderAddCmd{Alias: "my kc", Issuer: "https://keycloak.example.com", ClientID: "opkssh"},
			errorString: `invalid provider alias "my kc"`,
		},
		{
			name:        "client config that is not a mapping",
			existing:    []byte("- just\n- a list\n"),
			cmd:         ClientProviderAddCmd{Alias: "kc", Issuer: "https://keycloak.example.com", ClientID: "opkssh"},
			errorString: "client config is not a YAML mapping",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := afero.NewMemMapFs()
			if tt.existing != nil {
				require.NoError(t, fs.MkdirAll(filepath.Dir(configPath), 0o755))
				require.NoError(t, afero.WriteFile(fs, configPath, tt.existing, 0o600))
			}
			out := &bytes.Buffer{}
			cmd := tt.cmd
			cmd.Fs = fs
			cmd.Out = out
			cmd.ConfigPath = configPath

			err := cmd.Run()

			if tt.errorString != "" {
				require.ErrorContains(t, err, tt.errorString)
				content, readErr := afero.ReadFile(fs, configPath)
				require.NoError(t, readErr)
				require.Equal(t, string(tt.existing), string(content), "expected the client config to be unchanged")
				exists, _ := afero.Exists(fs, configPath+".tmp")
				require.False(t, exists)
				return
			}
			require.NoError(t, err)

			// Load the result the way opkssh login does
			clientConfig, err := config.GetClientConfigFromFile(configPath, fs)
			require.NoError(t, err)
			for _, provider := range clientConfig.Providers {
				_, err := provider.ToProvider(false)
				require.NoError(t, err, "provider %v", provider.AliasList)
			}
			content, err := afero.ReadFile(fs, configPath)
			require.NoError(t, err)
			tt.check(t, string(content), clientConfig)

			if tt.existing != nil {
				info, err := fs.Stat(configPath)
				require.NoError(t, err)
				require.Equal(t, "-rw-------", info.Mode().Perm().String(), "expected the file mode to be kept")
			}
			exists, _ := afero.Exists(fs, configPath+".tmp")
			require.False(t, exists)

			require.Contains(t, out.String(), tt.wantOut)
			require.Contains(t, out.String(), "add this line to /etc/opk/providers:\n  "+cmd.Issuer+" "+cmd.ClientID+" 24h\n")
		})
	}
}
