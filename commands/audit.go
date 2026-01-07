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
	"os/user"
	"path/filepath"
	"strings"

	"github.com/openpubkey/opkssh/policy"
	"github.com/spf13/afero"
)

// AuditCmd provides functionality to audit policy files against provider definitions
type AuditCmd struct {
	Fs                 afero.Fs
	Out                io.Writer
	ProviderLoader     policy.ProviderLoader
	SystemProviderPath string // Path to provider definitions
	SystemPolicyPath   string // Path to policy definitions
	CurrentUsername    string
	ProviderFilePath   string // Custom provider file path
	PolicyFilePath     string // Custom policy file path
	SkipUserPolicy     bool   // Skip auditing user policy file
}

// NewAuditCmd creates a new AuditCmd with default settings
func NewAuditCmd(out io.Writer) *AuditCmd {
	return &AuditCmd{
		Fs:                 afero.NewOsFs(),
		Out:                out,
		ProviderLoader:     policy.NewProviderFileLoader(),
		SystemProviderPath: policy.SystemDefaultProvidersPath,
		SystemPolicyPath:   policy.SystemDefaultPolicyPath,
		CurrentUsername:    getCurrentUsername(),
	}
}

// Run executes the audit command
// Returns exit code: 0 for success, 1 for warnings/errors
func (a *AuditCmd) Run() int {
	// Determine which provider file to use
	providerPath := a.SystemProviderPath
	if a.ProviderFilePath != "" {
		providerPath = a.ProviderFilePath
	}

	// Load providers first
	providerPolicy, err := a.ProviderLoader.LoadProviderPolicy(providerPath)
	if err != nil {
		if strings.Contains(err.Error(), "permission denied") {
			fmt.Fprintf(a.Out, "opkssh audit must be run as root, try `sudo opkssh audit` %s\n", providerPath)
		}
		fmt.Fprintf(a.Out, "ERROR: Failed to load providers from %s: %v\n", providerPath, err)
		return 1
	}

	// Create validator from provider policy
	validator := policy.NewPolicyValidator(providerPolicy)

	// Collect all validation results
	var allResults []policy.ValidationResult

	// Determine which policy file to use for system policy
	policyPath := policy.SystemDefaultPolicyPath
	if a.PolicyFilePath != "" {
		policyPath = a.PolicyFilePath
	}

	// Audit policy file
	systemResults, exists, err := a.auditPolicyFileWithStatus(policyPath, validator)
	if err != nil {
		fmt.Fprintf(a.Out, "ERROR: Failed to audit policy file: %v\n", err)
		return 1
	}

	if exists {
		fmt.Fprintf(a.Out, "\nValidating %s...\n\n", policyPath)
		for _, result := range systemResults {
			a.printResult(result)
		}
		allResults = append(allResults, systemResults...)
	}

	// Audit user policy file if it exists and not skipping
	if !a.SkipUserPolicy {

		// We read /etc/passwd to enumerate all the home directories to find auth_id policy files.
		var etcPasswdContent []byte
		etcPasswdpath := "/etc/passwd"
		if exists, err := afero.Exists(a.Fs, etcPasswdpath); err != nil {
			fmt.Fprintf(a.Out, "ERROR: Failed to read /etc/passwd to enumerate user home directories: %v\n", err)
			return 1
		} else if !exists {
			fmt.Fprintf(a.Out, "Error: /etc/passwd does not exist, cannot enumerate user home directories\n")
			return 1
		} else {
			etcPasswdContent, err = afero.ReadFile(a.Fs, etcPasswdpath)
			if err != nil {
				fmt.Fprintf(a.Out, "ERROR: Failed to read /etc/passwd (needed to enumerate user home directories): %v\n", err)
				return 1
			}

		}
		homeDirs := getHomeDirsFromEtcPasswd(string(etcPasswdContent))

		for _, row := range homeDirs {
			userPolicyPath := filepath.Join(row.HomeDir, ".opk", "auth_id")
			// TODO: Check misconfiguration where username does not matched current user
			userResults, userExists, err := a.auditPolicyFileWithStatus(userPolicyPath, validator)
			if err != nil {
				fmt.Fprintf(a.Out, "WARNING: Failed to audit user policy file at %s: %v\n", userPolicyPath, err)
				// Don't fail completely if user policy is unreadable
			} else if userExists {
				fmt.Fprintf(a.Out, "\nValidating %s...\n\n", userPolicyPath)
				for _, result := range userResults {
					a.printResult(result)
				}
				allResults = append(allResults, userResults...)
			}
		}
	}

	// Print summary only (results already printed above)
	if len(allResults) == 0 {
		fmt.Fprintf(a.Out, "\nNo policy entries to validate.\n")
	}

	// Print summary
	summary := policy.CalculateSummary(allResults)
	a.printSummary(summary)

	// Return appropriate exit code
	return summary.GetExitCode()
}

// auditPolicyFileWithStatus validates all entries in a policy file and returns results, whether file exists, and any errors
func (a *AuditCmd) auditPolicyFileWithStatus(policyPath string, validator *policy.PolicyValidator) ([]policy.ValidationResult, bool, error) {
	var results []policy.ValidationResult

	// Check if file exists
	exists, err := afero.Exists(a.Fs, policyPath)
	if err != nil {
		return nil, false, fmt.Errorf("failed to check if policy file exists: %w", err)
	}

	if !exists {
		// File doesn't exist, return empty results with exists=false
		return results, false, nil
	}

	// Load policy file
	content, err := afero.ReadFile(a.Fs, policyPath)
	if err != nil {
		return nil, true, fmt.Errorf("failed to read policy file: %w", err)
	}

	// Parse policy
	p := policy.FromTable(content, policyPath)

	lineNumber := 1
	for _, user := range p.Users {
		// Each user entry maps to principals
		for _, principal := range user.Principals {
			result := validator.ValidateEntry(principal, user.IdentityAttribute, user.Issuer, lineNumber)
			results = append(results, result)
		}
		lineNumber++
	}

	return results, true, nil
}

// printResult prints a single validation result
func (a *AuditCmd) printResult(result policy.ValidationResult) {
	var statusBadge string
	switch result.Status {
	case policy.StatusSuccess:
		statusBadge = "[OK]"
	case policy.StatusWarning:
		statusBadge = "[WARN]"
	case policy.StatusError:
		statusBadge = "[ERR]"
	}

	statusStr := fmt.Sprintf("%-8s", string(result.Status))
	fmt.Fprintf(a.Out, "%s %-8s: %s %s %s", statusBadge, statusStr, result.Principal, result.IdentityAttr, result.Issuer)

	if result.Reason != "" {
		fmt.Fprintf(a.Out, " (%s)", result.Reason)
	}

	fmt.Fprintf(a.Out, "\n")
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

type etcPasswdRow struct {
	Username string
	HomeDir  string
}

// getHomeDirsFromEtcPasswd parses /etc/passwd and returns a list of usernames
// and their associated home directories. This is not sufficient for all home
// directories as it does not consider home directories specified by NSS.
func getHomeDirsFromEtcPasswd(etcPasswd string) []etcPasswdRow {
	entries := []etcPasswdRow{}
	for _, line := range strings.Split(etcPasswd, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// /etc/passwd line is name:passwd:uid:gid:gecos:dir:shell
		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}
		if parts[5] == "" {
			continue
		}

		entry := etcPasswdRow{Username: parts[0], HomeDir: parts[5]}
		entries = append(entries, entry)
	}
	return entries
}
