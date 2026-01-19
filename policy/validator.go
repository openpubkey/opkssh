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

package policy

import (
	"fmt"
	"strings"
)

// ValidationStatus represents the validation result status
type ValidationStatus string

const (
	StatusSuccess ValidationStatus = "SUCCESS"
	StatusWarning ValidationStatus = "WARNING"
	StatusError   ValidationStatus = "ERROR"
)

// ValidationRowResult represents the result of validating a single policy entry
type ValidationRowResult struct {
	Status       ValidationStatus `json:"status"`
	Hints        []string         `json:"hints"`
	Principal    string           `json:"principal"`
	IdentityAttr string           `json:"identity_attr"`
	Issuer       string           `json:"issuer"`
	Reason       string           `json:"reason"`
	LineNumber   int              `json:"line_number"` // Line number in the policy file (1-indexed)
}

// PolicyValidator validates policy file entries against provider definitions
type PolicyValidator struct {
	// issuerMap maps issuer URL to ProvidersRow
	issuerMap map[string]ProvidersRow
}

// NewPolicyValidator creates a new PolicyValidator from a ProviderPolicy
func NewPolicyValidator(providerPolicy *ProviderPolicy) *PolicyValidator {
	issuerMap := make(map[string]ProvidersRow)
	for _, row := range providerPolicy.rows {
		issuerMap[row.Issuer] = row
	}

	return &PolicyValidator{
		issuerMap: issuerMap,
	}
}

// ValidateEntry validates a single policy entry against the provider definitions
func (v *PolicyValidator) ValidateEntry(principal, identityAttr, issuer string, lineNumber int) ValidationRowResult {
	result := ValidationRowResult{
		Principal:    principal,
		IdentityAttr: identityAttr,
		Hints:        []string{},
		Issuer:       issuer,
		LineNumber:   lineNumber,
	}

	if issuer == "" {
		result.Status = StatusError
		result.Reason = "issuer is empty"
		return result
	}

	// Check if issuer exists in providers (exact match)
	_, exists := v.issuerMap[issuer]
	if !exists {
		result.Status = StatusError
		result.Reason = "issuer not found in /etc/opk/providers"

		// issuer in policy file has a trailing slash, but issuer in provider file does not have a trailing slash
		if strings.HasSuffix(issuer, "/") {
			if almostMatchingIssuer, exists := v.issuerMap[issuer[0:len(issuer)-1]]; exists {
				result.Hints = append(result.Hints,
					fmt.Sprintf("Remove the trailing slash from the issuer URL (%s) to match provider entry (%s)",
						issuer, almostMatchingIssuer.Issuer))
				return result
			}
		}

		// issuer in policy file as is http, but issuer in provider is https
		httpIssuer := strings.Replace(issuer, "http://", "https://", 1)
		if almostMatchingIssuer, exists := v.issuerMap[httpIssuer]; exists {
			result.Hints = append(result.Hints,
				fmt.Sprintf("Change the scheme http:// of the issuer URL (%s) to match scheme https:// of provider (%s)",
					issuer, almostMatchingIssuer.Issuer))
			return result
		}

		// issuer in policy file as is https, but issuer in provider is http
		httpsIssuer := strings.Replace(issuer, "https://", "http://", 1)
		if almostMatchingIssuer, exists := v.issuerMap[httpsIssuer]; exists {
			result.Hints = append(result.Hints,
				fmt.Sprintf("Change the scheme https:// of the issuer URL (%s) to match scheme http:// of provider (%s)",
					issuer, almostMatchingIssuer.Issuer))
			return result
		}

		result.Hints = append(result.Hints,
			fmt.Sprintf("Ensure the issuer URL (%s) is correct and matches an entry in /etc/opk/providers", issuer))
		return result
	}

	if strings.HasSuffix(issuer, "/") {
		result.Status = StatusError
		result.Reason = fmt.Sprintf("issuer URI (%s) should not have a trailing slash /", issuer)
		result.Hints = append(result.Hints, "Remove the trailing slash from the issuer URL in both the policy and provider files")
		return result
	}

	// Issuer exists, entry is valid
	result.Status = StatusSuccess
	result.Reason = "issuer matches provider entry"

	if !strings.HasPrefix(issuer, "https://") {
		result.Status = StatusWarning
		result.Reason = "issuer does not use https scheme"
		result.Hints = append(result.Hints, "It is recommended to use https scheme for issuer URLs")
	}
	return result
}

// Summary holds aggregated statistics about validation results
type ValidationSummary struct {
	TotalTested int
	Successful  int
	Warnings    int
	Errors      int
}

// HasErrors returns true if there are any errors or warnings
func (s *ValidationSummary) HasErrors() bool {
	return s.Errors > 0 || s.Warnings > 0
}

// GetExitCode returns the appropriate exit code (0 for success, 1 for errors/warnings)
func (s *ValidationSummary) GetExitCode() int {
	if s.HasErrors() {
		return 1
	}
	return 0
}

// CalculateSummary calculates summary statistics from a list of validation results
func CalculateSummary(results []ValidationRowResult) ValidationSummary {
	summary := ValidationSummary{
		TotalTested: len(results),
	}

	for _, result := range results {
		switch result.Status {
		case StatusSuccess:
			summary.Successful++
		case StatusWarning:
			summary.Warnings++
		case StatusError:
			summary.Errors++
		}
	}

	return summary
}
