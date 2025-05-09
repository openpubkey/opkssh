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

	// Test failure
	clientConfigDefault, err = NewClientConfig([]byte("invalid yaml"))
	require.ErrorContains(t, err, "yaml: unmarshal errors")
	require.Nil(t, clientConfigDefault)
}
