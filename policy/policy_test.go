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

package policy_test

import (
	"testing"

	"github.com/openpubkey/opkssh/policy"
	"github.com/stretchr/testify/assert"
)

func TestAddAllowedPrincipal(t *testing.T) {
	t.Parallel()

	defaultIssuer := "https://example.com"

	// Test adding an allowed principal to an opkssh policy
	tests := []struct {
		name           string
		principal      string
		userEmail      string
		initialPolicy  *policy.Policy
		expectedPolicy *policy.Policy
	}{
		{
			name:          "empty policy",
			principal:     "test",
			userEmail:     "alice@example.com",
			initialPolicy: &policy.Policy{},
			expectedPolicy: &policy.Policy{
				Users: []policy.User{
					{
						IdentityAttribute: "alice@example.com",
						Principals:        []string{"test"},
						Issuer:            "https://example.com",
					},
				},
			},
		},
		{
			name:      "non-empty policy. user not found",
			principal: "test",
			userEmail: "bob@example.com",
			initialPolicy: &policy.Policy{
				Users: []policy.User{
					{
						IdentityAttribute: "alice@example.com",
						Principals:        []string{"test", "test2"},
						Issuer:            "https://example.com",
					},
				}},
			expectedPolicy: &policy.Policy{
				Users: []policy.User{
					{
						IdentityAttribute: "bob@example.com",
						Principals:        []string{"test"},
						Issuer:            "https://example.com",
					},
					{
						IdentityAttribute: "alice@example.com",
						Principals:        []string{"test", "test2"},
						Issuer:            "https://example.com",
					},
				},
			},
		},
		{
			name:      "user already exists. new principal",
			principal: "test3",
			userEmail: "alice@example.com",
			initialPolicy: &policy.Policy{
				Users: []policy.User{
					{
						IdentityAttribute: "alice@example.com",
						Principals:        []string{"test", "test2"},
						Issuer:            "https://example.com",
					},
				}},
			expectedPolicy: &policy.Policy{
				Users: []policy.User{
					{
						IdentityAttribute: "alice@example.com",
						Principals:        []string{"test", "test2", "test3"},
						Issuer:            "https://example.com",
					},
				},
			},
		},
		{
			name:      "user already exists. principal not new.",
			principal: "test",
			userEmail: "alice@example.com",
			initialPolicy: &policy.Policy{
				Users: []policy.User{
					{
						IdentityAttribute: "alice@example.com",
						Principals:        []string{"test"},
						Issuer:            "https://example.com",
					},
				}},
			expectedPolicy: &policy.Policy{
				Users: []policy.User{
					{
						IdentityAttribute: "alice@example.com",
						Principals:        []string{"test"},
						Issuer:            "https://example.com",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("AddAllowedPrincipal(principal=%s, userEmail=%s)", tt.principal, tt.userEmail)
			t.Logf("Initial policy: %#v", tt.initialPolicy)
			tt.initialPolicy.AddAllowedPrincipal(tt.principal, tt.userEmail, defaultIssuer)
			assert.ElementsMatch(t, tt.expectedPolicy.Users, tt.initialPolicy.Users)
		})
	}
}
