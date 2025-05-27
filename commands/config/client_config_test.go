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
	"testing"

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
