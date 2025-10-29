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
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openpubkey/opkssh/policy"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func policyToMapUsers(p *policy.Policy) map[string]policy.User {
	m := make(map[string]*policy.User)
	for e, user := range p.Users {
		if seenUserEntry, ok := m[user.IdentityAttribute]; ok {
			seenUserEntry.Principals = append(seenUserEntry.Principals, user.Principals...)
		} else {
			entry := p.Users[e]
			m[user.IdentityAttribute] = &entry
		}
	}

	mapWithValues := make(map[string]policy.User)
	for k, v := range m {
		// Safe because we never put nil in map above
		mapWithValues[k] = *v
	}
	return mapWithValues
}

func TestLoad(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// rootPolicy is the policy read from the system default policy path. If
		// nil the file will be missing
		rootPolicy *policy.Policy
		// userPolicy is the policy read from the ValidUser's home directory. If
		// nil the file will be missing
		userPolicy    *policy.Policy
		expectedUsers map[string]policy.User
		shouldError   bool
	}{
		{
			name:        "both policies are missing",
			rootPolicy:  nil,
			userPolicy:  nil,
			shouldError: true,
		},
		{
			name: "only root policy exists",
			rootPolicy: &policy.Policy{
				Users: []policy.User{
					{
						IdentityAttribute: "alice@example.com",
						Principals:        []string{"test"},
						Issuer:            "https://example.com",
					},
				},
			},
			expectedUsers: map[string]policy.User{
				"alice@example.com": {IdentityAttribute: "alice@example.com", Principals: []string{"test"}, Issuer: "https://example.com"},
			},
		},
		{
			name: "only user policy exists",
			userPolicy: &policy.Policy{
				Users: []policy.User{
					{
						IdentityAttribute: "alice@example.com",
						Principals:        []string{ValidUser.Username, "bob"},
						Issuer:            "https://example.com",
					},
				},
			},
			expectedUsers: map[string]policy.User{
				"alice@example.com": {IdentityAttribute: "alice@example.com", Principals: []string{ValidUser.Username}, Issuer: "https://example.com"},
			},
		},
		{
			name: "both user and root policy exist",
			rootPolicy: &policy.Policy{
				Users: []policy.User{
					{
						IdentityAttribute: "alice@example.com",
						Principals:        []string{"test"},
						Issuer:            "https://example.com",
					},
					{
						IdentityAttribute: "charlie@example.com",
						Principals:        []string{"test"},
						Issuer:            "https://example.com",
					},
				},
			},
			userPolicy: &policy.Policy{
				Users: []policy.User{
					{
						IdentityAttribute: "alice@example.com",
						Principals:        []string{ValidUser.Username},
						Issuer:            "https://example.com",
					},
					{
						IdentityAttribute: "bob@example.com",
						Principals:        []string{ValidUser.Username},
						Issuer:            "https://example.com",
					},
				},
			},
			expectedUsers: map[string]policy.User{
				"alice@example.com":   {IdentityAttribute: "alice@example.com", Principals: []string{"test", ValidUser.Username}, Issuer: "https://example.com"},
				"bob@example.com":     {IdentityAttribute: "bob@example.com", Principals: []string{ValidUser.Username}, Issuer: "https://example.com"},
				"charlie@example.com": {IdentityAttribute: "charlie@example.com", Principals: []string{"test"}, Issuer: "https://example.com"},
			},
		},
		{
			name: "both user and root policy exist but no valid user policy entries",
			rootPolicy: &policy.Policy{
				Users: []policy.User{
					{
						IdentityAttribute: "alice@example.com",
						Principals:        []string{"test"},
						Issuer:            "https://example.com",
					},
					{
						IdentityAttribute: "charlie@example.com",
						Principals:        []string{"test"},
						Issuer:            "https://example.com",
					},
				},
			},
			userPolicy: &policy.Policy{
				Users: []policy.User{
					{
						IdentityAttribute: "alice@example.com",
						Principals:        []string{"test"},
						Issuer:            "https://example.com",
					},
					{
						IdentityAttribute: "bob@example.com",
						Principals:        []string{"test", "test2"},
						Issuer:            "https://example.com",
					},
					{
						IdentityAttribute: "charlie@example.com",
						Principals:        []string{"test", "test2", "test3"},
						Issuer:            "https://example.com",
					},
				},
			},
			expectedUsers: map[string]policy.User{
				"alice@example.com":   {IdentityAttribute: "alice@example.com", Principals: []string{"test"}, Issuer: "https://example.com"},
				"charlie@example.com": {IdentityAttribute: "charlie@example.com", Principals: []string{"test"}, Issuer: "https://example.com"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockFs := afero.NewMemMapFs()

			// Init SUT on each sub-test
			multiFileLoader := &policy.MultiPolicyLoader{
				HomePolicyLoader:   NewTestHomePolicyLoader(mockFs, &MockUserLookup{User: ValidUser}),
				SystemPolicyLoader: NewTestSystemPolicyLoader(mockFs, &MockUserLookup{User: ValidUser}),
				LoaderScript:       MockTestSudoScript,
				Username:           ValidUser.Username,
			}

			t.Logf("Root policy: %#v", tt.rootPolicy)
			t.Logf("User policy: %#v", tt.userPolicy)

			// Create files at expected paths
			expectedPaths := []string{}
			if tt.rootPolicy != nil {
				policyFile, err := tt.rootPolicy.ToTable()
				require.NoError(t, err)
				err = afero.WriteFile(mockFs, policy.SystemDefaultPolicyPath, policyFile, 0640)
				require.NoError(t, err)
				expectedPaths = append(expectedPaths, policy.SystemDefaultPolicyPath)
			}
			if tt.userPolicy != nil {
				policyFile, err := tt.userPolicy.ToTable()
				require.NoError(t, err)
				expectedPath := filepath.Join(ValidUser.HomeDir, ".opk", "auth_id")
				err = afero.WriteFile(mockFs, expectedPath, policyFile, 0600)
				require.NoError(t, err)
				expectedPaths = append(expectedPaths, expectedPath)
			}

			policy, source, err := multiFileLoader.Load()

			if tt.shouldError {
				require.Error(t, err)
				require.Nil(t, policy, "should not return policy if error")
				require.Empty(t, source.Source(), "should not return source if error")
			} else {
				// Check error
				require.NoError(t, err)

				// Check paths
				paths := strings.Split(source.Source(), ",")
				var pathsCleaned []string
				for _, p := range paths {
					pathsCleaned = append(pathsCleaned, strings.TrimSpace(p))
				}
				require.ElementsMatch(t, expectedPaths, pathsCleaned)

				// Check user entries
				gotUsers := policyToMapUsers(policy)
				for email, expectedEntry := range tt.expectedUsers {
					gotEntry, ok := gotUsers[email]
					if assert.True(t, ok, "policy should have entry for email %s", email) {
						assert.Equal(t, expectedEntry.IdentityAttribute, gotEntry.IdentityAttribute)
						assert.ElementsMatch(t, expectedEntry.Principals, gotEntry.Principals)
					}
				}
			}
		})
	}
}

func MockTestSudoScript(_ *policy.HomePolicyLoader, username string) ([]byte, error) {
	return []byte{}, fmt.Errorf("mock error")
}
