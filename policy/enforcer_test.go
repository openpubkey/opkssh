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
	"context"
	"fmt"
	"testing"

	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/providers/mocks"
	"github.com/openpubkey/opkssh/policy"
	"github.com/stretchr/testify/require"
)

func NewMockOpenIdProvider(t *testing.T) providers.OpenIdProvider {
	providerOpts := providers.DefaultMockProviderOpts()
	op, _, idTokenTemplate, err := providers.NewMockProvider(providerOpts)
	require.NoError(t, err)
	idTokenTemplate.ExtraClaims = map[string]any{"email": "arthur.aardvark@example.com"}
	return op
}

func NewMockOpenIdSubProvider(t *testing.T, sub string) providers.OpenIdProvider {
	providerOpts := providers.DefaultMockProviderOpts()
	op, _, idTokenTemplate, err := providers.NewMockProvider(providerOpts)
	require.NoError(t, err)
	idTokenTemplate.ExtraClaims = map[string]any{"sub": sub}
	return op
}

func NewMockOpenIdProviderGroups(t *testing.T, groups []string) providers.OpenIdProvider {
	providerOpts := providers.DefaultMockProviderOpts()
	op, _, idTokenTemplate, err := providers.NewMockProvider(providerOpts)
	require.NoError(t, err)
	idTokenTemplate.ExtraClaims = map[string]any{"email": "arthur.aardvark@example.com", "groups": groups}
	return op
}

func NewMockOpenIdProvider2(gqSign bool, issuer string, clientID string, extraClaims map[string]any) (providers.OpenIdProvider, *mocks.MockProviderBackend, error) {
	providerOpts := providers.MockProviderOpts{
		Issuer:     issuer,
		ClientID:   clientID,
		GQSign:     gqSign,
		NumKeys:    2,
		CommitType: providers.CommitTypesEnum.NONCE_CLAIM,
		VerifierOpts: providers.ProviderVerifierOpts{
			CommitType:        providers.CommitTypesEnum.NONCE_CLAIM,
			SkipClientIDCheck: false,
			GQOnly:            false,
			ClientID:          clientID,
		},
	}

	op, mockBackend, _, err := providers.NewMockProvider(providerOpts)
	if err != nil {
		return nil, nil, err
	}

	expSigningKey, expKeyID, expRecord := mockBackend.RandomSigningKey()

	idTokenTemplate := &mocks.IDTokenTemplate{
		CommitFunc:  mocks.AddNonceCommit,
		Issuer:      op.Issuer(),
		Aud:         clientID,
		KeyID:       expKeyID,
		Alg:         expRecord.Alg,
		ExtraClaims: extraClaims,
		SigningKey:  expSigningKey,
	}
	mockBackend.SetIDTokenTemplate(idTokenTemplate)

	return op, mockBackend, nil
}

var policyTest = &policy.Policy{
	Users: []policy.User{
		{
			IdentityAttribute: "alice@bastionzero.com",
			Principals:        []string{"test"},
			Issuer:            "https://accounts.example.com",
		},
		{
			IdentityAttribute: "arthur.aardvark@example.com",
			Principals:        []string{"test"},
			Issuer:            "https://accounts.example.com",
		},
		{
			IdentityAttribute: "bob@example.com",
			Principals:        []string{"test"},
			Issuer:            "https://accounts.example.com",
		},
	},
}

var policyTestNoEntry = &policy.Policy{
	Users: []policy.User{
		{
			IdentityAttribute: "alice@bastionzero.com",
			Principals:        []string{"test"},
		},
		{
			IdentityAttribute: "bob@example.com",
			Principals:        []string{"test"},
		},
	},
}

var policyWithOidcGroup = &policy.Policy{
	Users: []policy.User{
		{
			IdentityAttribute: "oidc:groups:a",
			Principals:        []string{"test"},
			Issuer:            "https://accounts.example.com",
		},
	},
}

type MockPolicyLoader struct {
	// Policy is returned on any call to Load() if Error is nil
	Policy *policy.Policy
	// Error is returned on any call to Load() if non-nil
	Error error
}

var _ policy.Loader = &MockPolicyLoader{}

// Load implements policy.Loader.
func (m *MockPolicyLoader) Load() (*policy.Policy, policy.Source, error) {
	if m.Error == nil {
		return m.Policy, MockSource{}, nil
	} else {
		return nil, nil, m.Error
	}
}

var _ policy.Source = &MockSource{}

// MockSource is used to signal that a source if from a mock.
type MockSource struct{}

func (MockSource) Source() string { return "<mock data>" }

func TestPolicyApproved(t *testing.T) {
	t.Parallel()

	op := NewMockOpenIdProvider(t)

	opkClient, err := client.New(op)
	require.NoError(t, err)
	pkt, err := opkClient.Auth(context.Background())
	require.NoError(t, err)

	policyEnforcer := &policy.Enforcer{
		PolicyLoader: &MockPolicyLoader{Policy: policyTest},
	}

	// Check that policy file is properly parsed and checked
	err = policyEnforcer.CheckPolicy("test", pkt, "", "example-base64Cert", "ssh-rsa")
	require.NoError(t, err)
}

func TestPolicyEmailDifferentCase(t *testing.T) {
	t.Parallel()

	op := NewMockOpenIdProvider(t)

	opkClient, err := client.New(op)
	require.NoError(t, err)
	pkt, err := opkClient.Auth(context.Background())
	require.NoError(t, err)

	policyWithDiffCapitalizationThanEmail := &policy.Policy{
		Users: []policy.User{
			{
				IdentityAttribute: "ArThuR.AArdVARK@Example.COM",
				Principals:        []string{"test"},
				Issuer:            "https://accounts.example.com",
			},
		},
	}

	policyEnforcer := &policy.Enforcer{
		PolicyLoader: &MockPolicyLoader{Policy: policyWithDiffCapitalizationThanEmail},
	}

	err = policyEnforcer.CheckPolicy("test", pkt, "", "example-base64Cert", "ssh-rsa")
	require.NoError(t, err, "user should have access despite email capitalization differences")
}

func TestPolicySub(t *testing.T) {
	t.Parallel()

	op := NewMockOpenIdSubProvider(t, "repo:organization/repository:ref:refs/heads/main")
	opkClient, err := client.New(op)
	require.NoError(t, err)
	pkt, err := opkClient.Auth(context.Background())
	require.NoError(t, err)

	policyWithDiffCapitalizationThanEmail := &policy.Policy{
		Users: []policy.User{
			{
				IdentityAttribute: "repo:organization/repository:ref:refs/heads/main",
				Principals:        []string{"test"},
				Issuer:            "https://accounts.example.com",
			},
		},
	}

	policyEnforcer := &policy.Enforcer{
		PolicyLoader: &MockPolicyLoader{Policy: policyWithDiffCapitalizationThanEmail},
	}

	err = policyEnforcer.CheckPolicy("test", pkt, "", "example-base64Cert", "ssh-rsa")
	require.NoError(t, err, "user should have access on main branch")
}

func TestPolicyDeniedBadUser(t *testing.T) {
	t.Parallel()

	op := NewMockOpenIdProvider(t)

	opkClient, err := client.New(op)
	require.NoError(t, err)
	pkt, err := opkClient.Auth(context.Background())
	require.NoError(t, err)

	policyEnforcer := &policy.Enforcer{
		PolicyLoader: &MockPolicyLoader{Policy: policyTest},
	}

	err = policyEnforcer.CheckPolicy("baduser", pkt, "", "example-base64Cert", "ssh-rsa")
	require.Error(t, err, "user should not have access")
}

func TestPolicyDeniedNoUserEntry(t *testing.T) {
	t.Parallel()

	op := NewMockOpenIdProvider(t)

	opkClient, err := client.New(op)
	require.NoError(t, err)
	pkt, err := opkClient.Auth(context.Background())
	require.NoError(t, err)

	policyEnforcer := &policy.Enforcer{
		PolicyLoader: &MockPolicyLoader{Policy: policyTestNoEntry},
	}

	err = policyEnforcer.CheckPolicy("test", pkt, "", "example-base64Cert", "ssh-rsa")
	require.Error(t, err, "user should not have access")
}

func TestPolicyDeniedWrongIssuer(t *testing.T) {
	t.Parallel()

	op := NewMockOpenIdProvider(t)

	opkClient, err := client.New(op)
	require.NoError(t, err)
	pkt, err := opkClient.Auth(context.Background())
	require.NoError(t, err)

	policyWithDiffCapitalizationThanEmail := &policy.Policy{
		Users: []policy.User{
			{
				IdentityAttribute: "arthur.aardvark@example.com",
				Principals:        []string{"test"},
				Issuer:            "https://differentIssuer.example.com",
			},
		},
	}

	policyEnforcer := &policy.Enforcer{
		PolicyLoader: &MockPolicyLoader{Policy: policyWithDiffCapitalizationThanEmail},
	}

	err = policyEnforcer.CheckPolicy("test", pkt, "", "example-base64Cert", "ssh-rsa")
	require.Error(t, err, "user should not have access due to wrong issuer")
}

func TestPolicyApprovedOidcGroups(t *testing.T) {
	t.Parallel()

	op := NewMockOpenIdProviderGroups(t, []string{"a", "b", "c"})

	opkClient, err := client.New(op)
	require.NoError(t, err)
	pkt, err := opkClient.Auth(context.Background())
	require.NoError(t, err)

	policyEnforcer := &policy.Enforcer{
		PolicyLoader: &MockPolicyLoader{Policy: policyWithOidcGroup},
	}

	err = policyEnforcer.CheckPolicy("test", pkt, "", "example-base64Cert", "ssh-rsa")
	require.NoError(t, err)
}

func TestPolicyApprovedOidcGroupWithAtSign(t *testing.T) {
	t.Parallel()

	op := NewMockOpenIdProviderGroups(t, []string{"it.infra@my_domain.com"})

	policyLine := &policy.Policy{
		Users: []policy.User{
			{
				IdentityAttribute: "oidc:groups:it.infra@my_domain.com",
				Principals:        []string{"test"},
				Issuer:            "https://accounts.example.com",
			},
		},
	}

	opkClient, err := client.New(op)
	require.NoError(t, err)
	pkt, err := opkClient.Auth(context.Background())
	require.NoError(t, err)

	policyEnforcer := &policy.Enforcer{
		PolicyLoader: &MockPolicyLoader{Policy: policyLine},
	}

	err = policyEnforcer.CheckPolicy("test", pkt, "", "example-base64Cert", "ssh-rsa")
	require.NoError(t, err)
}

func TestPolicyDeniedOidcGroups(t *testing.T) {
	t.Parallel()

	op := NewMockOpenIdProviderGroups(t, []string{"z"})

	opkClient, err := client.New(op)
	require.NoError(t, err)
	pkt, err := opkClient.Auth(context.Background())
	require.NoError(t, err)

	policyEnforcer := &policy.Enforcer{
		PolicyLoader: &MockPolicyLoader{Policy: policyWithOidcGroup},
	}

	err = policyEnforcer.CheckPolicy("test", pkt, "", "example-base64Cert", "ssh-rsa")
	require.Error(t, err, "user should not as they don't have group 'c'")
}

func TestPolicyDeniedMissingOidcGroupsClaim(t *testing.T) {
	t.Parallel()

	op := NewMockOpenIdProvider(t)

	opkClient, err := client.New(op)
	require.NoError(t, err)
	pkt, err := opkClient.Auth(context.Background())
	require.NoError(t, err)

	policyEnforcer := &policy.Enforcer{
		PolicyLoader: &MockPolicyLoader{Policy: policyWithOidcGroup},
	}

	err = policyEnforcer.CheckPolicy("test", pkt, "", "example-base64Cert", "ssh-rsa")
	require.Error(t, err, "user should not as the token is missing the groups claim")
}

func TestEnforceTableTest(t *testing.T) {
	t.Parallel()

	policyWithOidcGroup := &policy.Policy{
		Users: []policy.User{
			{
				IdentityAttribute: "oidc:groups:group2",
				Principals:        []string{"test"},
				Issuer:            "https://accounts.example.com",
			},
		},
	}
	tests := []struct {
		name          string
		op            providers.OpenIdProvider
		policyLoader  policy.Loader
		userInfoJson  string
		expectedError string
	}{
		{
			name:         "Happy path (No userinfo supplied but ID Token has groups claim)",
			op:           NewMockOpenIdProviderGroups(t, []string{"group1", "group2"}),
			policyLoader: &MockPolicyLoader{Policy: policyWithOidcGroup},
		},
		{
			name:          "No groups claim in ID Token",
			op:            NewMockOpenIdProvider(t),
			policyLoader:  &MockPolicyLoader{Policy: policyWithOidcGroup},
			expectedError: "no policy to allow",
		},
		{
			name: "Happy path (Valid user info)",
			// We set an email that does not match the email claim in the ID Token, as emails do not need to match, only subs
			op:           NewMockOpenIdProvider(t),
			userInfoJson: `{"sub": "me", "email": "non-matching-email@example.com", "name": "Alice Example", "groups": ["group1", "group2"]}`,
			policyLoader: &MockPolicyLoader{Policy: policyWithOidcGroup},
		},
		{
			name:          "Missing groups claim in userinfo",
			op:            NewMockOpenIdProvider(t),
			userInfoJson:  `{"sub": "me", "email": "non-matching-email@example.com", "name": "Alice Example"}`,
			policyLoader:  &MockPolicyLoader{Policy: policyWithOidcGroup},
			expectedError: "no policy to allow",
		},
		{
			name:          "Wrong groups claim in userinfo",
			op:            NewMockOpenIdProvider(t),
			userInfoJson:  `{"sub": "me", "email": "non-matching-email@example.com", "name": "Alice Example", "groups": ["wrongGroup1", "wrongGroup2"]}`,
			policyLoader:  &MockPolicyLoader{Policy: policyWithOidcGroup},
			expectedError: "no policy to allow",
		},
		{
			name:          "sub in userinfo does not match sub in ID Token does not match",
			op:            NewMockOpenIdProvider(t),
			userInfoJson:  `{"sub": "not-me", "email": "non-matching-email@example.com", "name": "Alice Example", "groups": ["group1", "group2"]}`,
			policyLoader:  &MockPolicyLoader{Policy: policyWithOidcGroup},
			expectedError: "userInfo sub claim (not-me) does not match user policy sub claim (me)",
		},
		{
			name:          "corrupted userinfo",
			op:            NewMockOpenIdProvider(t),
			userInfoJson:  `{"sub": "me`,
			policyLoader:  &MockPolicyLoader{Policy: policyWithOidcGroup},
			expectedError: "error unmarshalling claims from userinfo endpoint",
		},
		{
			name:          "policy loader failure",
			op:            NewMockOpenIdProvider(t),
			userInfoJson:  `{"sub": "me`,
			policyLoader:  &MockPolicyLoader{Error: fmt.Errorf("error loading policy")},
			expectedError: "error loading policy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			opkClient, err := client.New(tt.op)
			require.NoError(t, err)
			pkt, err := opkClient.Auth(context.Background())
			require.NoError(t, err)

			policyEnforcer := &policy.Enforcer{
				PolicyLoader: tt.policyLoader,
			}

			err = policyEnforcer.CheckPolicy("test", pkt, tt.userInfoJson, "example-base64Cert", "ssh-rsa")
			if tt.expectedError != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectedError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
