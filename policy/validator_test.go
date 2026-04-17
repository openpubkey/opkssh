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
	"github.com/stretchr/testify/require"
)

// TestValidateEntry tests policy validation
func TestValidateEntry(t *testing.T) {
	t.Parallel()

	// Create a provider policy with test data
	providerPolicy := &policy.ProviderPolicy{}
	providerPolicy.AddRow(policy.ProvidersRow{
		Issuer:           "https://accounts.google.com",
		ClientID:         "google-client-id",
		ExpirationPolicy: "24h",
	})
	providerPolicy.AddRow(policy.ProvidersRow{
		Issuer:           "https://auth.example.com",
		ClientID:         "example-client-id",
		ExpirationPolicy: "24h",
	})
	providerPolicy.AddRow(policy.ProvidersRow{
		Issuer:           "http://op.example.com",
		ClientID:         "example-client-id",
		ExpirationPolicy: "24h",
	})
	providerPolicy.AddRow(policy.ProvidersRow{
		Issuer:           "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
		ClientID:         "azure-client-id",
		ExpirationPolicy: "24h",
	})
	providerPolicy.AddRow(policy.ProvidersRow{
		Issuer:           "https://trailing.slash.example.com/",
		ClientID:         "example-client-id",
		ExpirationPolicy: "24h",
	})

	validator := policy.NewPolicyValidator(providerPolicy)

	tests := []struct {
		name                   string
		principal              string
		identityAttr           string
		issuer                 string
		expectedStatus         policy.ValidationStatus
		expectedReasonContains string
		expectedHints          []string
	}{
		{
			name:                   "SUCCESS: Full URL matching provider",
			principal:              "root",
			identityAttr:           "alice@mail.com",
			issuer:                 "https://accounts.google.com",
			expectedStatus:         policy.StatusSuccess,
			expectedReasonContains: "issuer matches provider entry",
		},
		{
			name:                   "SUCCESS: Custom provider with matching full URL",
			principal:              "dev",
			identityAttr:           "bob@example.com",
			issuer:                 "https://auth.example.com",
			expectedStatus:         policy.StatusSuccess,
			expectedReasonContains: "issuer matches provider entry",
		},
		{
			name:                   "ERROR: Using google alias",
			principal:              "root",
			identityAttr:           "alice@mail.com",
			issuer:                 "google",
			expectedStatus:         policy.StatusError,
			expectedReasonContains: "issuer not found",
		},
		{
			name:                   "ERROR: Using azure alias",
			principal:              "root",
			identityAttr:           "alice@mail.com",
			issuer:                 "azure",
			expectedStatus:         policy.StatusError,
			expectedReasonContains: "issuer not found",
		},
		{
			name:                   "ERROR: Issuer not found",
			principal:              "root",
			identityAttr:           "charlie@mail.com",
			issuer:                 "https://auth.notfound.com",
			expectedStatus:         policy.StatusError,
			expectedReasonContains: "issuer not found",
		},
		{
			name:                   "ERROR: Missing protocol prefix",
			principal:              "root",
			identityAttr:           "alice@mail.com",
			issuer:                 "auth.example.com",
			expectedStatus:         policy.StatusError,
			expectedReasonContains: "issuer not found",
		},
		{
			name:                   "ERROR: Unknown alias",
			principal:              "root",
			identityAttr:           "alice@mail.com",
			issuer:                 "unknownalias",
			expectedStatus:         policy.StatusError,
			expectedReasonContains: "issuer not found",
		},
		{
			name:                   "ERROR: Issuer is empty",
			principal:              "root",
			identityAttr:           "alice@mail.com",
			issuer:                 "",
			expectedStatus:         policy.StatusError,
			expectedReasonContains: "issuer is empty",
		},
		{
			name:                   "ERROR: almost match between issuer and provider issuer (trailing slash)",
			principal:              "root",
			identityAttr:           "alice@mail.com",
			issuer:                 "https://auth.example.com/",
			expectedStatus:         policy.StatusError,
			expectedReasonContains: "issuer not found",
			expectedHints:          []string{"Remove the trailing slash from the issuer URL"},
		},
		{
			name:                   "ERROR: trailing slash in issuer URL",
			principal:              "root",
			identityAttr:           "alice@mail.com",
			issuer:                 "https://trailing.slash.example.com/",
			expectedStatus:         policy.StatusError,
			expectedReasonContains: "issuer URI (https://trailing.slash.example.com/) should not have a trailing slash",
			expectedHints:          []string{"Remove the trailing slash from the issuer URL"},
		},
		{
			name:                   "ERROR: http vs https mismatch",
			principal:              "root",
			identityAttr:           "alice@mail.com",
			issuer:                 "http://auth.example.com",
			expectedStatus:         policy.StatusError,
			expectedReasonContains: "issuer not found",
			expectedHints:          []string{"Change the scheme http:// of the issuer URL (http://auth.example.com) to match scheme https:// of provider (https://auth.example.com)"},
		},
		{
			name:                   "ERROR: https vs http mismatch",
			principal:              "root",
			identityAttr:           "alice@mail.com",
			issuer:                 "https://op.example.com",
			expectedStatus:         policy.StatusError,
			expectedReasonContains: "issuer not found",
			expectedHints:          []string{"Change the scheme https:// of the issuer URL (https://op.example.com) to match scheme http:// of provider (http://op.example.com)"},
		},
		{
			name:                   "WARNING: http warning",
			principal:              "root",
			identityAttr:           "alice@mail.com",
			issuer:                 "http://op.example.com",
			expectedStatus:         policy.StatusWarning,
			expectedReasonContains: "issuer does not use https scheme",
			expectedHints:          []string{"It is recommended to use https scheme for issuer URLs"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.ValidateEntry(tt.principal, tt.identityAttr, tt.issuer, 1)

			require.Equal(t, tt.expectedStatus, result.Status)
			if tt.expectedReasonContains != "" {
				require.Contains(t, result.Reason, tt.expectedReasonContains)
			}
			if len(tt.expectedHints) > 0 {
				require.Len(t, result.Hints, len(tt.expectedHints))
				for i, expectedHint := range tt.expectedHints {
					require.Contains(t, result.Hints[i], expectedHint)
				}
			}
		})
	}
}

// TestValidationSummary tests the summary calculation
func TestValidationSummary(t *testing.T) {
	t.Parallel()

	results := []policy.ValidationRowResult{
		{Status: policy.StatusSuccess, Principal: "root", IdentityAttr: "alice@mail.com", Issuer: "google"},
		{Status: policy.StatusSuccess, Principal: "dev", IdentityAttr: "bob@mail.com", Issuer: "https://accounts.google.com"},
		{Status: policy.StatusWarning, Principal: "root", IdentityAttr: "charlie@mail.com", Issuer: "azure"},
		{Status: policy.StatusError, Principal: "root", IdentityAttr: "diana@mail.com", Issuer: "https://notfound.com"},
		{Status: policy.StatusError, Principal: "root", IdentityAttr: "eve@mail.com", Issuer: "badproto.com"},
	}

	summary := policy.CalculateSummary(results)

	require.Equal(t, 5, summary.TotalTested)
	require.Equal(t, 2, summary.Successful)
	require.Equal(t, 1, summary.Warnings)
	require.Equal(t, 2, summary.Errors)
	require.True(t, summary.HasErrors())
	require.Equal(t, 1, summary.GetExitCode())
}

// TestValidationSummaryNoErrors tests summary with no errors/warnings
func TestValidationSummaryNoErrors(t *testing.T) {
	t.Parallel()

	results := []policy.ValidationRowResult{
		{Status: policy.StatusSuccess, Principal: "root", IdentityAttr: "alice@mail.com", Issuer: "google"},
		{Status: policy.StatusSuccess, Principal: "dev", IdentityAttr: "bob@mail.com", Issuer: "https://accounts.google.com"},
	}

	summary := policy.CalculateSummary(results)

	require.Equal(t, 2, summary.TotalTested)
	require.Equal(t, 2, summary.Successful)
	require.Equal(t, 0, summary.Warnings)
	require.Equal(t, 0, summary.Errors)
	require.False(t, summary.HasErrors())
	require.Equal(t, 0, summary.GetExitCode())
}

// TestPolicyValidatorAliasResolution tests that aliases resolve correctly
func TestPolicyValidatorAliasResolution(t *testing.T) {
	t.Parallel()

	providerPolicy := &policy.ProviderPolicy{}
	providerPolicy.AddRow(policy.ProvidersRow{
		Issuer:           "https://accounts.google.com",
		ClientID:         "google-client-id",
		ExpirationPolicy: "24h",
	})
	providerPolicy.AddRow(policy.ProvidersRow{
		Issuer:           "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
		ClientID:         "microsoft-client-id",
		ExpirationPolicy: "24h",
	})

	validator := policy.NewPolicyValidator(providerPolicy)

	// We do not currently support alias in the auth_id issuer field
	result := validator.ValidateEntry("root", "alice@mail.com", "google", 1)
	require.Equal(t, policy.StatusError, result.Status)
	require.Equal(t, "google", result.Issuer)

	result = validator.ValidateEntry("root", "alice@mail.com", "microsoft", 1)
	require.Equal(t, policy.StatusError, result.Status)
}

// TestEmptyValidationResults tests empty validation results
func TestEmptyValidationResults(t *testing.T) {
	t.Parallel()

	var results []policy.ValidationRowResult
	summary := policy.CalculateSummary(results)

	require.Equal(t, 0, summary.TotalTested)
	require.Equal(t, 0, summary.Successful)
	require.Equal(t, 0, summary.Warnings)
	require.Equal(t, 0, summary.Errors)
	require.False(t, summary.HasErrors())
	require.Equal(t, 0, summary.GetExitCode())
}
