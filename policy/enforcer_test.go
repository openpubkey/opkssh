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
	"testing"

	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/providers/mocks"
	"github.com/openpubkey/opkssh/policy"
	"github.com/stretchr/testify/require"
)

func NewMockOpenIdProvider() (providers.OpenIdProvider, error) {
	providerOpts := providers.DefaultMockProviderOpts()
	op, _, idTokenTemplate, err := providers.NewMockProvider(providerOpts)
	idTokenTemplate.ExtraClaims = map[string]any{"email": "arthur.aardvark@example.com"}

	return op, err
}

func NewMockOpenIdProviderGroups(groups []string) (providers.OpenIdProvider, error) {
	providerOpts := providers.DefaultMockProviderOpts()
	op, _, idTokenTemplate, err := providers.NewMockProvider(providerOpts)
	idTokenTemplate.ExtraClaims = map[string]any{"email": "arthur.aardvark@example.com", "groups": groups}

	return op, err
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
		return m.Policy, policy.EmptySource{}, nil
	} else {
		return nil, nil, m.Error
	}
}

func TestPolicyApproved(t *testing.T) {
	t.Parallel()

	op, err := NewMockOpenIdProvider()
	require.NoError(t, err)

	opkClient, err := client.New(op)
	require.NoError(t, err)
	pkt, err := opkClient.Auth(context.Background())
	require.NoError(t, err)

	policyEnforcer := &policy.Enforcer{
		PolicyLoader: &MockPolicyLoader{Policy: policyTest},
	}

	// Check that policy file is properly parsed and checked
	err = policyEnforcer.CheckPolicy("test", pkt)
	require.NoError(t, err)
}

func TestPolicyEmailDifferentCase(t *testing.T) {
	t.Parallel()

	op, err := NewMockOpenIdProvider()
	require.NoError(t, err)

	opkClient, err := client.New(op)
	require.NoError(t, err)
	pkt, err := opkClient.Auth(context.Background())
	require.NoError(t, err)

	var policyWithDiffCapitalizationThanEmail = &policy.Policy{
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

	err = policyEnforcer.CheckPolicy("test", pkt)
	require.NoError(t, err, "user should have access despite email capitalization differences")
}

func TestPolicyDeniedBadUser(t *testing.T) {
	t.Parallel()

	op, err := NewMockOpenIdProvider()
	require.NoError(t, err)

	opkClient, err := client.New(op)
	require.NoError(t, err)
	pkt, err := opkClient.Auth(context.Background())
	require.NoError(t, err)

	policyEnforcer := &policy.Enforcer{
		PolicyLoader: &MockPolicyLoader{Policy: policyTest},
	}

	err = policyEnforcer.CheckPolicy("baduser", pkt)
	require.Error(t, err, "user should not have access")
}

func TestPolicyDeniedNoUserEntry(t *testing.T) {
	t.Parallel()

	op, err := NewMockOpenIdProvider()
	require.NoError(t, err)

	opkClient, err := client.New(op)
	require.NoError(t, err)
	pkt, err := opkClient.Auth(context.Background())
	require.NoError(t, err)

	policyEnforcer := &policy.Enforcer{
		PolicyLoader: &MockPolicyLoader{Policy: policyTestNoEntry},
	}

	err = policyEnforcer.CheckPolicy("test", pkt)
	require.Error(t, err, "user should not have access")
}

func TestPolicyDeniedWrongIssuer(t *testing.T) {
	t.Parallel()

	op, err := NewMockOpenIdProvider()
	require.NoError(t, err)

	opkClient, err := client.New(op)
	require.NoError(t, err)
	pkt, err := opkClient.Auth(context.Background())
	require.NoError(t, err)

	var policyWithDiffCapitalizationThanEmail = &policy.Policy{
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

	err = policyEnforcer.CheckPolicy("test", pkt)
	require.Error(t, err, "user should not have access due to wrong issuer")
}

func TestPolicyApprovedOidcGroups(t *testing.T) {
	t.Parallel()

	op, err := NewMockOpenIdProviderGroups([]string{"a", "b", "c"})

	require.NoError(t, err)

	opkClient, err := client.New(op)
	require.NoError(t, err)
	pkt, err := opkClient.Auth(context.Background())
	require.NoError(t, err)

	policyEnforcer := &policy.Enforcer{
		PolicyLoader: &MockPolicyLoader{Policy: policyWithOidcGroup},
	}

	err = policyEnforcer.CheckPolicy("test", pkt)
	require.NoError(t, err)
}

func TestPolicyApprovedOidcGroupWithAtSign(t *testing.T) {
	t.Parallel()

	op, err := NewMockOpenIdProviderGroups([]string{"it.infra@my_domain.com"})

	policyLine := &policy.Policy{
		Users: []policy.User{
			{
				IdentityAttribute: "oidc:groups:it.infra@my_domain.com",
				Principals:        []string{"test"},
				Issuer:            "https://accounts.example.com",
			},
		},
	}

	require.NoError(t, err)

	opkClient, err := client.New(op)
	require.NoError(t, err)
	pkt, err := opkClient.Auth(context.Background())
	require.NoError(t, err)

	policyEnforcer := &policy.Enforcer{
		PolicyLoader: &MockPolicyLoader{Policy: policyLine},
	}

	err = policyEnforcer.CheckPolicy("test", pkt)
	require.NoError(t, err)
}

func TestPolicyDeniedOidcGroups(t *testing.T) {
	t.Parallel()

	op, err := NewMockOpenIdProviderGroups([]string{"z"})

	require.NoError(t, err)

	opkClient, err := client.New(op)
	require.NoError(t, err)
	pkt, err := opkClient.Auth(context.Background())
	require.NoError(t, err)

	policyEnforcer := &policy.Enforcer{
		PolicyLoader: &MockPolicyLoader{Policy: policyWithOidcGroup},
	}

	err = policyEnforcer.CheckPolicy("test", pkt)
	require.Error(t, err, "user should not as they don't have group 'c'")
}

func TestPolicyDeniedMissingOidcGroupsClaim(t *testing.T) {
	t.Parallel()

	op, err := NewMockOpenIdProvider()

	require.NoError(t, err)

	opkClient, err := client.New(op)
	require.NoError(t, err)
	pkt, err := opkClient.Auth(context.Background())
	require.NoError(t, err)

	policyEnforcer := &policy.Enforcer{
		PolicyLoader: &MockPolicyLoader{Policy: policyWithOidcGroup},
	}

	err = policyEnforcer.CheckPolicy("test", pkt)
	require.Error(t, err, "user should not as the token is missing the groups claim")
}
