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
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/openpubkey/opkssh/policy"
	"github.com/openpubkey/opkssh/policy/files"
	"github.com/spf13/afero"
)

// AuditCmd provides functionality to audit policy files against provider definitions
type AuditCmd struct {
	Fs               afero.Fs
	Out              io.Writer
	ErrOut           io.Writer
	filePermsChecker files.PermsChecker
	aclVerifier      files.ACLVerifier
	ProviderLoader   policy.ProviderLoader
	CurrentUsername  string

	// Args
	ProviderPath   string // Custom provider file path
	PolicyPath     string // Custom policy file path
	JsonOutput     bool   // Output results in JSON format
	SkipUserPolicy bool   // Skip auditing user policy file
}

// NewAuditCmd creates a new AuditCmd with default settings
func NewAuditCmd(out io.Writer, errOut io.Writer) *AuditCmd {
	fs := afero.NewOsFs()
	return &AuditCmd{
		Fs:              fs,
		Out:             out,
		ErrOut:          errOut,
		ProviderLoader:  policy.NewProviderFileLoader(),
		CurrentUsername: getCurrentUsername(),
		filePermsChecker: files.PermsChecker{
			Fs:        fs,
			CmdRunner: files.ExecCmd,
		},
		aclVerifier: files.NewDefaultACLVerifier(fs),

		ProviderPath:   policy.SystemDefaultProvidersPath,
		PolicyPath:     policy.SystemDefaultPolicyPath,
		SkipUserPolicy: isWindows(),
	}
}

func (a *AuditCmd) Audit(opksshVersion string) (*TotalResults, error) {
	providerPath := a.ProviderPath
	policyPath := a.PolicyPath

	totalResults := &TotalResults{
		Username:   a.CurrentUsername,
		OpkVersion: opksshVersion,
	}

	// Load providers first
	providerPolicy, err := a.ProviderLoader.LoadProviderPolicy(providerPath)
	if err != nil {
		if strings.Contains(err.Error(), "permission denied") {
			fmt.Fprint(a.ErrOut, "opkssh audit must be run as root, try `sudo opkssh audit`\n")
		}
		return nil, fmt.Errorf("failed to load providers (%s): %v", providerPath, err)
	}
	totalResults.ProviderFile = ProviderResults{
		FilePath: providerPath,
	}

	// Create validator from provider policy
	validator := policy.NewPolicyValidator(providerPolicy)

	// Audit policy file
	systemResults, exists, err := a.auditPolicyFileWithStatus(policyPath, []fs.FileMode{files.ModeSystemPerms}, validator)
	if err != nil {
		return nil, fmt.Errorf("failed to audit policy file: %v", err)
	}
	totalResults.SystemPolicyFile = *systemResults

	if exists {
		fmt.Fprintf(a.ErrOut, "\nvalidating %s...\n", policyPath)
		if !a.JsonOutput {
			for _, result := range systemResults.Rows {
				a.printResult(result)
			}
		}
	}

	// Audit user policy file if it exists and not skipping
	if !a.SkipUserPolicy {
		if isWindows() {
			fmt.Fprint(a.ErrOut, "skipping user policy audit on Windows (no /etc/passwd)\n")
		} else {
			// We read /etc/passwd to enumerate all the home directories to find auth_id policy files.
			var etcPasswdContent []byte
			passwdPath := "/etc/passwd"
			if exists, err := afero.Exists(a.Fs, passwdPath); !exists {
				return nil, fmt.Errorf("failed to read /etc/passwd: /etc/passwd not found (needed to enumerate user home policies)")
			} else if err != nil {
				return nil, fmt.Errorf("failed to read /etc/passwd: %v", err)
			} else {
				etcPasswdContent, err = afero.ReadFile(a.Fs, passwdPath)
				if err != nil {
					return nil, fmt.Errorf("failed to read /etc/passwd: %v", err)
				}
			}
			homeDirs := getHomeDirsFromEtcPasswd(string(etcPasswdContent))
			for _, row := range homeDirs {
				userPolicyPath := filepath.Join(row.HomeDir, ".opk", "auth_id")

				userResults, userExists, err := a.auditPolicyFileWithStatus(userPolicyPath, []fs.FileMode{files.ModeHomePerms}, validator)
				if err != nil {
					fmt.Fprintf(a.ErrOut, "failed to audit user policy file at %s: %v\n", userPolicyPath, err)
					totalResults.HomePolicyFiles = append(totalResults.HomePolicyFiles,
						PolicyFileResult{FilePath: userPolicyPath, Error: err.Error()})
					// Don't fail completely if user policy is unreadable
				} else if userExists {
					fmt.Fprintf(a.ErrOut, "\nvalidating %s...\n", userPolicyPath)
					if !a.JsonOutput {
						for _, result := range userResults.Rows {
							a.printResult(result)
						}
					}
					totalResults.HomePolicyFiles = append(totalResults.HomePolicyFiles, *userResults)
				}
			}
		}
	}

	totalResults.SetOpenSSHVersion()
	totalResults.SetOsInfo()
	totalResults.SetOk()

	return totalResults, nil
}

// Run executes the audit command returns an error if it can't perform the
// audit or if the audit finds errors or warnings in system configuration.
// The opksshVersion parameter is the current opkssh version string.
func (a *AuditCmd) Run(opksshVersion string) error {
	totalResults, err := a.Audit(opksshVersion)
	if err != nil {
		return err
	}

	// Print summary only (results already printed above)
	if len(totalResults.HomePolicyFiles) == 0 && len(totalResults.SystemPolicyFile.Rows) == 0 {
		fmt.Fprint(a.ErrOut, "\nno policy entries to validate\n")
	}

	// Collect all validation results
	allResults := []policy.ValidationRowResult{}
	allResults = append(allResults, totalResults.SystemPolicyFile.Rows...)
	for _, homePolicy := range totalResults.HomePolicyFiles {
		allResults = append(allResults, homePolicy.Rows...)
	}
	summary := policy.CalculateSummary(allResults)

	if a.JsonOutput {
		jsonBytes, err := json.MarshalIndent(totalResults, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON output: %v", err)
		} else {
			fmt.Fprintln(a.Out, string(jsonBytes))
		}
	} else {
		a.printSummary(summary)
	}

	if summary.HasErrors() {
		return fmt.Errorf("audit completed and discovered errors")
	}
	return nil
}

// auditPolicyFileWithStatus validates all entries in a policy file and returns results, whether file exists, and any errors
func (a *AuditCmd) auditPolicyFileWithStatus(policyPath string, requiredPerms []fs.FileMode, validator *policy.PolicyValidator) (*PolicyFileResult, bool, error) {
	results := &PolicyFileResult{
		FilePath: policyPath,
		Rows:     []policy.ValidationRowResult{},
	}

	// Check if file exists
	exists, err := afero.Exists(a.Fs, policyPath)
	if err != nil {
		return nil, false, fmt.Errorf("failed to check if policy file exists: %w", err)
	}

	if !exists {
		// File doesn't exist, return empty results with exists=false
		return results, false, nil
	}

	if permsErr := a.filePermsChecker.CheckPerm(policyPath, requiredPerms, "", ""); permsErr != nil {
		results.PermsError = permsErr.Error()
	}

	// Check ACLs if verifier is available (Windows-specific)
	if a.aclVerifier != nil {
		report, err := a.aclVerifier.VerifyACL(policyPath, expectedSystemACL(requiredPerms[0]))
		if err == nil && len(report.Problems) > 0 {
			for _, problem := range report.Problems {
				fmt.Fprintf(a.ErrOut, "  ACL issue: %s\n", problem)
			}
		}
	}

	// Load policy file
	content, err := afero.ReadFile(a.Fs, policyPath)
	if err != nil {
		return nil, true, fmt.Errorf("failed to read policy file: %w", err)
	}

	rowDetailsList := files.ReadRowsWithDetails(content)
	for i, rowDetails := range rowDetailsList {
		lineNumber := i + 1

		if rowDetails.Empty {
			continue
		}
		if rowDetails.Error != nil {
			result := policy.ValidationRowResult{
				Status:     policy.StatusError,
				Reason:     rowDetails.Error.Error(),
				LineNumber: lineNumber,
			}
			results.Rows = append(results.Rows, result)
			continue
		}

		// We break the table by rows and then feed each row as if it is its own table record the line number of error
		p, problems := policy.FromTable([]byte(rowDetails.Content), policyPath)
		if len(problems) > 0 {
			result := policy.ValidationRowResult{
				Status:     policy.StatusError,
				Reason:     problems[0].ErrorMessage,
				LineNumber: lineNumber,
			}
			results.Rows = append(results.Rows, result)
			continue
		}
		for _, user := range p.Users {
			// Each user entry maps to principals
			for _, principal := range user.Principals {
				result := validator.ValidateEntry(principal, user.IdentityAttribute, user.Issuer, lineNumber)
				results.Rows = append(results.Rows, result)
			}
		}
	}
	return results, true, nil
}

// printResult prints a single validation result
func (a *AuditCmd) printResult(result policy.ValidationRowResult) {
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
		fmt.Fprintf(a.Out, " (%s) ", result.Reason)
	}

	for _, hint := range result.Hints {
		fmt.Fprintf(a.Out, " - %s ", hint)
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
