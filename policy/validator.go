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

// ValidationResult represents the result of validating a single policy entry
type ValidationResult struct {
	Status         ValidationStatus
	Principal      string
	IdentityAttr   string
	Issuer         string
	Reason         string
	ResolvedIssuer string // For alias resolution, the full issuer URL
	LineNumber     int    // Line number in the policy file (1-indexed)
}

// PolicyValidator validates policy file entries against provider definitions
type PolicyValidator struct {
	// issuerMap maps issuer URL to ProvidersRow
	issuerMap map[string]ProvidersRow
	// aliasMap maps alias to issuer URL
	aliasMap map[string]string
}

// NewPolicyValidator creates a new PolicyValidator from a ProviderPolicy
func NewPolicyValidator(providerPolicy *ProviderPolicy) *PolicyValidator {
	issuerMap := make(map[string]ProvidersRow)
	for _, row := range providerPolicy.rows {
		issuerMap[row.Issuer] = row
	}

	// Build the alias map for predefined providers
	aliasMap := make(map[string]string)
	aliasMap["google"] = "https://accounts.google.com"
	aliasMap["azure"] = "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0"
	aliasMap["microsoft"] = "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0"
	aliasMap["gitlab"] = "https://gitlab.com"
	aliasMap["hello"] = "https://issuer.hello.coop"

	return &PolicyValidator{
		issuerMap: issuerMap,
		aliasMap:  aliasMap,
	}
}

// ValidateEntry validates a single policy entry against the provider definitions
func (v *PolicyValidator) ValidateEntry(principal, identityAttr, issuer string, lineNumber int) ValidationResult {
	result := ValidationResult{
		Principal:    principal,
		IdentityAttr: identityAttr,
		Issuer:       issuer,
		LineNumber:   lineNumber,
	}

	// Check if issuer is a known alias
	if aliasIssuer, isAlias := v.aliasMap[issuer]; isAlias {
		result.ResolvedIssuer = aliasIssuer
		// Check if the resolved issuer exists in providers
		if _, exists := v.issuerMap[aliasIssuer]; exists {
			result.Status = StatusWarning
			result.Reason = fmt.Sprintf("using alias instead of full URL %s", aliasIssuer)
			return result
		}
		// Alias resolved but issuer not in providers (shouldn't happen for predefined aliases)
		result.Status = StatusError
		result.Reason = fmt.Sprintf("alias '%s' resolves to %s, but issuer not found in providers", issuer, aliasIssuer)
		return result
	}

	// If not an alias, it must be a full issuer URL - exact match required
	result.ResolvedIssuer = issuer

	// Check if issuer exists in providers (exact match)
	_, exists := v.issuerMap[issuer]
	if !exists {
		result.Status = StatusError
		result.Reason = fmt.Sprintf("issuer not found in /etc/opk/providers")
		return result
	}

	// Issuer exists, entry is valid
	result.Status = StatusSuccess
	result.Reason = "issuer matches provider entry"

	// Log if both http and https variants exist
	httpIssuer := strings.Replace(issuer, "https://", "http://", 1)

	if strings.HasPrefix(issuer, "https://") {
		if _, httpExists := v.issuerMap[httpIssuer]; httpExists {
			// Both https and http exist - this is expected for custom providers
			result.Reason += " (note: both http:// and https:// variants exist in providers)"
		}
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
func CalculateSummary(results []ValidationResult) ValidationSummary {
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
