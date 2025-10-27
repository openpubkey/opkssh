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

func TestNewServerConfig(t *testing.T) {
	tests := []struct {
		name     string
		yamlData string
		want     *ServerConfig
		wantErr  bool
	}{
		{
			name: "auto_provision_users enabled",
			yamlData: `---
auto_provision_users: true
`,
			want: &ServerConfig{
				AutoProvisionUsers: true,
			},
			wantErr: false,
		},
		{
			name: "auto_provision_users disabled",
			yamlData: `---
auto_provision_users: false
`,
			want: &ServerConfig{
				AutoProvisionUsers: false,
			},
			wantErr: false,
		},
		{
			name: "auto_provision_users not specified",
			yamlData: `---
env_vars:
  TEST_VAR: "test_value"
`,
			want: &ServerConfig{
				AutoProvisionUsers: false,
				EnvVars: map[string]string{
					"TEST_VAR": "test_value",
				},
			},
			wantErr: false,
		},
		{
			name: "complete config with auto_provision_users",
			yamlData: `---
auto_provision_users: true
env_vars:
  TEST_VAR: "test_value"
deny_users:
  - "baduser"
deny_emails:
  - "bad@example.com"
`,
			want: &ServerConfig{
				AutoProvisionUsers: true,
				EnvVars: map[string]string{
					"TEST_VAR": "test_value",
				},
				DenyUsers:  []string{"baduser"},
				DenyEmails: []string{"bad@example.com"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewServerConfig([]byte(tt.yamlData))
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want.AutoProvisionUsers, got.AutoProvisionUsers)
			require.Equal(t, tt.want.EnvVars, got.EnvVars)
			require.Equal(t, tt.want.DenyUsers, got.DenyUsers)
			require.Equal(t, tt.want.DenyEmails, got.DenyEmails)
		})
	}
}
