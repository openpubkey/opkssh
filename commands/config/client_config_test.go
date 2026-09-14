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

package config

import (
	"os"
	"runtime"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

func TestParseConfig(t *testing.T) {
	clientConfigDefault, err := NewClientConfig(DefaultClientConfig)
	require.NoError(t, err)
	require.NotNil(t, clientConfigDefault)
	require.Equal(t, clientConfigDefault.DefaultProvider, "webchooser")
	require.Equal(t, 4, len(clientConfigDefault.Providers))

	providerMap, err := clientConfigDefault.GetProvidersMap()
	require.NoError(t, err)
	// This is 5 rather than 4 because one of the providers has 2 aliases
	require.Equal(t, 5, len(providerMap))

	for _, provider := range clientConfigDefault.Providers {
		require.NotEmpty(t, provider.Issuer, "Provider issuer should not be empty")
		require.False(t, provider.SendAccessToken, "SendAccessToken should be false by default")
	}

	provider, found := clientConfigDefault.GetByIssuer("https://accounts.google.com")
	require.NotEmpty(t, provider, "Provider should found since it exists in the config")
	require.True(t, found)

	provider, found = clientConfigDefault.GetByIssuer("https://not-a-real-provider.example.com")
	require.Nil(t, provider, "Provider should not found since it does not exist in the config")
	require.False(t, found)

	// Test failure
	clientConfigDefault, err = NewClientConfig([]byte("invalid yaml"))
	require.ErrorContains(t, err, "yaml: unmarshal errors")
	require.Nil(t, clientConfigDefault)
}

func TestParseConfigWithSendAccessToken(t *testing.T) {
	c := `---
default_provider: webchooser

providers:
  - alias: google
    issuer: https://accounts.google.com
    client_id: 206584157355-7cbe4s640tvm7naoludob4ut1emii7sf.apps.googleusercontent.com
    client_secret: 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
    scopes: openid email profile
    access_type: offline
    send_access_token: true
    prompt: consent
    redirect_uris:
      - http://localhost:3000/login-callback
      - http://localhost:10001/login-callback
      - http://localhost:11110/login-callback`

	clientConfig, err := NewClientConfig([]byte(c))
	require.NoError(t, err)
	require.NotNil(t, clientConfig)
	require.Equal(t, clientConfig.Providers[0].SendAccessToken, true)
}

func TestParseConfigWithAgentLifetime(t *testing.T) {
	// Both value shapes must parse into the string field: a duration string
	// and a bare integer number of seconds.
	for _, lifetime := range []string{"12h", "28800"} {
		c := `---
agent_lifetime: ` + lifetime + `
providers:
  - alias: google
    issuer: https://accounts.google.com
    client_id: test-client-id`

		clientConfig, err := NewClientConfig([]byte(c))
		require.NoError(t, err)
		require.NotNil(t, clientConfig)
		require.Equal(t, lifetime, clientConfig.AgentLifetime)
	}
}

func TestResolveClientConfigPath(t *testing.T) {
	const home = "/home/testuser"
	xdgPath := "/xdg-config/opk/config.yml"
	platformPath := home + "/.config/opk/config.yml"
	legacyPath := home + "/.opk/config.yml"

	tests := []struct {
		name      string
		xdgEnv    string
		files     []string
		explicit  string
		expected  string
		wantFound bool
	}{
		{
			name:      "explicit path is used as-is",
			explicit:  "/tmp/custom.yml",
			files:     []string{legacyPath},
			expected:  "/tmp/custom.yml",
			wantFound: false,
		},
		{
			name:      "XDG set and file exists there",
			xdgEnv:    "/xdg-config",
			files:     []string{xdgPath, legacyPath},
			expected:  xdgPath,
			wantFound: true,
		},
		{
			name:      "XDG replaces the platform dir, it does not stack",
			xdgEnv:    "/xdg-config",
			files:     []string{platformPath},
			expected:  xdgPath, // ~/.config is never consulted; no legacy -> chain head
			wantFound: false,
		},
		{
			name:      "relative XDG value is ignored per the spec",
			xdgEnv:    "relative/dir",
			files:     []string{platformPath},
			expected:  platformPath,
			wantFound: true,
		},
		{
			name:      "platform dir file wins over legacy",
			files:     []string{platformPath, legacyPath},
			expected:  platformPath,
			wantFound: true,
		},
		{
			name:      "legacy config keeps working when it is the only one",
			files:     []string{legacyPath},
			expected:  legacyPath,
			wantFound: true,
		},
		{
			// The common upgrade scenario: XDG in the environment, but the
			// user's only config is the legacy one.
			name:      "XDG set but only legacy exists: legacy wins",
			xdgEnv:    "/xdg-config",
			files:     []string{legacyPath},
			expected:  legacyPath,
			wantFound: true,
		},
		{
			name:      "no config anywhere resolves to the chain head for creation",
			files:     nil,
			expected:  platformPath,
			wantFound: false,
		},
		{
			name:      "no config anywhere with XDG set resolves to the XDG head",
			xdgEnv:    "/xdg-config",
			files:     nil,
			expected:  xdgPath,
			wantFound: false,
		},
	}

	if runtime.GOOS == "windows" {
		// Same guard as TestConfigureSSHHomeDirError: the home directory is
		// not resolved via HOME on Windows, and unix-style absolute paths
		// are not absolute there, so the table's paths cannot apply.
		t.Skip("home directory is not resolved via HOME on Windows")
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HOME", home)
			t.Setenv("XDG_CONFIG_HOME", tt.xdgEnv)

			fs := afero.NewMemMapFs()
			for _, f := range tt.files {
				require.NoError(t, afero.WriteFile(fs, f, []byte("---\n"), 0o600))
			}

			configPath := tt.explicit
			found, err := ResolveClientConfigPath(fs, &configPath)
			require.NoError(t, err)
			require.Equal(t, tt.expected, configPath)
			require.Equal(t, tt.wantFound, found)
		})
	}
}

func TestCreateDefaultClientConfigPerms(t *testing.T) {
	// The client config can carry provider client_secret values, so new
	// creates must be 0700 (dir) / 0600 (file).
	fs := afero.NewMemMapFs()
	configPath := "/home/testuser/.config/opk/config.yml"
	require.NoError(t, CreateDefaultClientConfig(configPath, fs))

	fileInfo, err := fs.Stat(configPath)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), fileInfo.Mode().Perm())

	dirInfo, err := fs.Stat("/home/testuser/.config/opk")
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o700), dirInfo.Mode().Perm())
}
