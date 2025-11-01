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

package commands

import (
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"

	"github.com/openpubkey/opkssh/policy"
	"github.com/spf13/afero"
)

// AuditCmd provides functionality to audit policy files against provider definitions
type AuditCmd struct {
	Fs               afero.Fs
	Out              io.Writer
	ProviderLoader   *policy.ProviderFileLoader
	SystemPolicyPath string
	UserPolicyLookup UserLookup
	CurrentUsername  string
}

// UserLookup defines the interface for looking up user information
type UserLookup interface {
	Lookup(username string) (*user.User, error)
}

// OsUserLookup implements UserLookup using os/user
type OsUserLookup struct{}

func (OsUserLookup) Lookup(username string) (*user.User, error) {
	return user.Lookup(username)
}

// NewAuditCmd creates a new AuditCmd with default settings
func NewAuditCmd(out io.Writer) *AuditCmd {
	return &AuditCmd{
		Fs:               afero.NewOsFs(),
		Out:              out,
		ProviderLoader:   policy.NewProviderFileLoader(),
		SystemPolicyPath: policy.SystemDefaultPolicyPath,
		UserPolicyLookup: OsUserLookup{},
		CurrentUsername:  getCurrentUsername(),
	}
}

// Run executes the audit command
// Returns exit code: 0 for success, 1 for warnings/errors
func (a *AuditCmd) Run() error {
	// Load providers first
	providerPolicy, err := a.ProviderLoader.LoadProviderPolicy(a.SystemPolicyPath)
	if err != nil {
		fmt.Fprintf(a.Out, "ERROR: Failed to load providers from /etc/opk/providers: %v\n", err)
		return fmt.Errorf("failed to load providers: %w", err)
	}

	// Create validator from provider policy
	validator := policy.NewPolicyValidator(providerPolicy)

	// Collect all validation results
	var allResults []policy.ValidationResult

	// Audit system policy file
	systemResults, err := a.auditPolicyFile(policy.SystemDefaultPolicyPath, validator)
	if err != nil {
		fmt.Fprintf(a.Out, "ERROR: Failed to audit system policy file: %v\n", err)
		return fmt.Errorf("failed to audit system policy file: %w", err)
	}
	allResults = append(allResults, systemResults...)

	// Audit user policy file if it exists
	userPolicyPath, err := a.getUserPolicyPath()
	if err == nil && userPolicyPath != "" {
		userResults, err := a.auditPolicyFile(userPolicyPath, validator)
		if err != nil {
			fmt.Fprintf(a.Out, "WARNING: Failed to audit user policy file at %s: %v\n", userPolicyPath, err)
			// Don't fail completely if user policy is unreadable
		} else {
			allResults = append(allResults, userResults...)
		}
	}

	// Print results
	a.printResults(allResults)

	// Print summary
	summary := policy.CalculateSummary(allResults)
	a.printSummary(summary)

	// Return appropriate exit code
	if summary.GetExitCode() != 0 {
		return fmt.Errorf("audit found issues")
	}

	return nil
}

// auditPolicyFile validates all entries in a policy file
func (a *AuditCmd) auditPolicyFile(policyPath string, validator *policy.PolicyValidator) ([]policy.ValidationResult, error) {
	var results []policy.ValidationResult

	// Check if file exists
	exists, err := afero.Exists(a.Fs, policyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to check if policy file exists: %w", err)
	}

	if !exists {
		// File doesn't exist, return empty results (not an error)
		fmt.Fprintf(a.Out, "\nValidating %s...\n", policyPath)
		fmt.Fprintf(a.Out, "(file does not exist, skipping)\n")
		return results, nil
	}

	// Load policy file
	content, err := afero.ReadFile(a.Fs, policyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}

	// Parse policy
	p := policy.FromTable(content, policyPath)

	fmt.Fprintf(a.Out, "\nValidating %s...\n\n", policyPath)

	lineNumber := 1
	for _, user := range p.Users {
		// Each user entry maps to principals
		for _, principal := range user.Principals {
			result := validator.ValidateEntry(principal, user.IdentityAttribute, user.Issuer, lineNumber)
			results = append(results, result)
			a.printResult(result)
		}
		lineNumber++
	}

	return results, nil
}

// getUserPolicyPath returns the path to the user's policy file, or empty string if not found
func (a *AuditCmd) getUserPolicyPath() (string, error) {
	if a.CurrentUsername == "" {
		return "", nil
	}

	u, err := a.UserPolicyLookup.Lookup(a.CurrentUsername)
	if err != nil {
		// User not found, return empty (not an error)
		return "", nil
	}

	userPolicyPath := filepath.Join(u.HomeDir, ".opk", "auth_id")
	return userPolicyPath, nil
}

// printResult prints a single validation result
func (a *AuditCmd) printResult(result policy.ValidationResult) {
	var statusSymbol string
	switch result.Status {
	case policy.StatusSuccess:
		statusSymbol = "✓"
	case policy.StatusWarning:
		statusSymbol = "⚠"
	case policy.StatusError:
		statusSymbol = "✗"
	}

	statusStr := fmt.Sprintf("%-8s", string(result.Status))
	fmt.Fprintf(a.Out, "%s %-8s: %s %s %s", statusSymbol, statusStr, result.Principal, result.IdentityAttr, result.Issuer)

	if result.Reason != "" {
		fmt.Fprintf(a.Out, " (%s)", result.Reason)
	}

	fmt.Fprintf(a.Out, "\n")
}

// printResults prints all validation results with a file header
func (a *AuditCmd) printResults(results []policy.ValidationResult) {
	if len(results) == 0 {
		fmt.Fprintf(a.Out, "\nNo policy entries to validate.\n")
		return
	}

	// Group results by file
	fileMap := make(map[string][]policy.ValidationResult)
	for _, result := range results {
		// Track which file the result came from (we can infer from context)
		// For now, just collect all and print
	}

	for _, result := range results {
		a.printResult(result)
	}
}

// printSummary prints the validation summary
func (a *AuditCmd) printSummary(summary policy.ValidationSummary) {
	fmt.Fprintf(a.Out, "\n=== SUMMARY ===\n")
	fmt.Fprintf(a.Out, "Total Entries Tested:  %d\n", summary.TotalTested)
	fmt.Fprintf(a.Out, "Successful:            %d\n", summary.Successful)
	fmt.Fprintf(a.Out, "Warnings:              %d\n", summary.Warnings)
	fmt.Fprintf(a.Out, "Errors:                %d\n", summary.Errors)
	fmt.Fprintf(a.Out, "\nExit Code: %d", summary.GetExitCode())
	if summary.GetExitCode() == 0 {
		fmt.Fprintf(a.Out, " (no issues detected)\n")
	} else if summary.Errors > 0 {
		fmt.Fprintf(a.Out, " (errors detected)\n")
	} else {
		fmt.Fprintf(a.Out, " (warnings detected)\n")
	}
}

// getCurrentUsername returns the current user's username
func getCurrentUsername() string {
	u, err := user.Current()
	if err != nil {
		return ""
	}
	return u.Username
}
