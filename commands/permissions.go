// Copyright 2026 OpenPubkey
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
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/openpubkey/opkssh/policy"
	"github.com/openpubkey/opkssh/policy/files"
	"github.com/openpubkey/opkssh/policy/plugins"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
)

// defaultConfirmPrompt reads a yes/no answer from stdin.
func defaultConfirmPrompt(prompt string, in io.Reader) (bool, error) {
	fmt.Print(prompt)
	r := bufio.NewReader(in)
	s, err := r.ReadString('\n')
	if err != nil {
		return false, err
	}
	s = strings.TrimSpace(strings.ToLower(s))
	return s == "y" || s == "yes", nil
}

// PermissionsCmd provides functionality to check and fix file permissions
type PermissionsCmd struct {
	FileSystem    files.FileSystem
	Out           io.Writer
	ErrOut        io.Writer
	In            io.Reader
	IsElevatedFn  func() (bool, error)
	ConfirmPrompt func(string, io.Reader) (bool, error)

	// Flags
	DryRun     bool
	Yes        bool
	Verbose    bool
	JsonOutput bool
}

// NewPermissionsCmd creates a new PermissionsCmd with default settings
func NewPermissionsCmd(out io.Writer, errOut io.Writer) *PermissionsCmd {
	return &PermissionsCmd{
		FileSystem:    files.NewFileSystem(afero.NewOsFs()),
		Out:           out,
		ErrOut:        errOut,
		In:            os.Stdin,
		IsElevatedFn:  IsElevated,
		ConfirmPrompt: defaultConfirmPrompt,
	}
}

// CobraCommand returns the cobra command tree for the permissions command.
func (p *PermissionsCmd) CobraCommand() *cobra.Command {
	permissionsCmd := &cobra.Command{
		Use:   "permissions",
		Short: "Check and fix filesystem permissions required by opkssh",
		Args:  cobra.NoArgs,
	}

	checkCmd := &cobra.Command{
		Use:   "check",
		Short: "Verify permissions and ownership for opkssh files",
		RunE: func(cmd *cobra.Command, args []string) error {
			return p.Check()
		},
	}
	checkCmd.Flags().BoolVarP(&p.JsonOutput, "json", "j", false, "Output results in JSON")

	fixCmd := &cobra.Command{
		Use:   "fix",
		Short: "Fix permissions and ownership for opkssh files (requires admin)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return p.Fix()
		},
	}
	fixCmd.Flags().BoolVar(&p.DryRun, "dry-run", false, "Don't modify anything; show planned changes")
	fixCmd.Flags().BoolVarP(&p.Yes, "yes", "y", false, "Apply changes without confirmation")
	fixCmd.Flags().BoolVarP(&p.Verbose, "verbose", "v", false, "Verbose output")
	fixCmd.Flags().BoolVarP(&p.JsonOutput, "json", "j", false, "Output results in JSON")

	installCmd := &cobra.Command{
		Use:   "install",
		Short: "Idempotent installer-friendly permissions fix (non-interactive)",
		RunE: func(cmd *cobra.Command, args []string) error {
			// installers expect non-interactive behavior; force yes=true
			p.Yes = true
			return p.Fix()
		},
	}
	installCmd.Flags().BoolVar(&p.DryRun, "dry-run", false, "Don't modify anything; show planned changes")
	installCmd.Flags().BoolVarP(&p.Verbose, "verbose", "v", false, "Verbose output")

	permissionsCmd.AddCommand(checkCmd)
	permissionsCmd.AddCommand(fixCmd)
	permissionsCmd.AddCommand(installCmd)
	return permissionsCmd
}

// checkResult is the JSON-serializable result of a permissions check.
type checkResult struct {
	Path     string `json:"path"`
	Exists   bool   `json:"exists"`
	PermsErr string `json:"permsErr,omitempty"`
	ACLErr   string `json:"aclErr,omitempty"`
}

// Check verifies permissions and ownership for opkssh files.
func (p *PermissionsCmd) Check() error {
	var problems []string
	var results []checkResult

	// checkACLResult is a helper that processes ACL findings from
	// CheckFilePermissions and appends them to problems/checkResult.
	checkACLResult := func(path string, result PermCheckResult, cr *checkResult) {
		if result.ACLErr != nil {
			problems = append(problems, fmt.Sprintf("%s: acl verify error: %v", path, result.ACLErr))
			cr.ACLErr = result.ACLErr.Error()
		} else if result.ACLReport != nil {
			report := result.ACLReport
			if report.OwnerSIDStr != "" {
				fmt.Fprintf(p.Out, "%s: owner=%s ownerSID=%s mode=%o\n", path, report.Owner, report.OwnerSIDStr, report.Mode)
			} else {
				fmt.Fprintf(p.Out, "%s: owner=%s mode=%o\n", path, report.Owner, report.Mode)
			}
			if len(report.ACEs) > 0 {
				fmt.Fprintln(p.Out, "  ACEs:")
				for _, a := range report.ACEs {
					if a.PrincipalSIDStr != "" {
						fmt.Fprintf(p.Out, "    - %s [%s]: %s (%s) inherited=%v\n", a.Principal, a.PrincipalSIDStr, a.Type, a.Rights, a.Inherited)
					} else {
						fmt.Fprintf(p.Out, "    - %s: %s (%s) inherited=%v\n", a.Principal, a.Type, a.Rights, a.Inherited)
					}
				}
			}
			for _, prob := range report.Problems {
				fmt.Fprintln(p.Out, "  ACL problem:", prob)
			}
		}
	}

	// System policy file — use shared permission check
	sp := files.RequiredPerms.SystemPolicy
	systemPolicy := policy.SystemDefaultPolicyPath
	sysResult := CheckFilePermissions(p.FileSystem, systemPolicy, sp)
	if !sysResult.Exists {
		problems = append(problems, fmt.Sprintf("%s: file does not exist", systemPolicy))
		results = append(results, checkResult{Path: systemPolicy, Exists: false})
	} else {
		cr := checkResult{Path: systemPolicy, Exists: true, PermsErr: sysResult.PermsErr}
		if sysResult.PermsErr != "" {
			problems = append(problems, fmt.Sprintf("%s: %s", systemPolicy, sysResult.PermsErr))
		}
		checkACLResult(systemPolicy, sysResult, &cr)
		results = append(results, cr)
	}

	// Providers file
	providersFile := policy.SystemDefaultProvidersPath
	pp := files.RequiredPerms.Providers
	provResult := CheckFilePermissions(p.FileSystem, providersFile, pp)
	if !provResult.Exists {
		// not fatal, but report
		problems = append(problems, fmt.Sprintf("%s: file does not exist", providersFile))
		results = append(results, checkResult{Path: providersFile, Exists: false})
	} else {
		cr := checkResult{Path: providersFile, Exists: true, PermsErr: provResult.PermsErr}
		if provResult.PermsErr != "" {
			problems = append(problems, fmt.Sprintf("%s: %s", providersFile, provResult.PermsErr))
		}
		checkACLResult(providersFile, provResult, &cr)
		results = append(results, cr)
	}

	// Config file
	configFile := filepath.Join(policy.GetSystemConfigBasePath(), "config.yml")
	cp := files.RequiredPerms.Config
	cfgResult := CheckFilePermissions(p.FileSystem, configFile, cp)
	if cfgResult.Exists {
		cr := checkResult{Path: configFile, Exists: true, PermsErr: cfgResult.PermsErr}
		if cfgResult.PermsErr != "" {
			problems = append(problems, fmt.Sprintf("%s: %s", configFile, cfgResult.PermsErr))
		}
		checkACLResult(configFile, cfgResult, &cr)
		results = append(results, cr)
	}

	// Policy plugins dir
	pluginsDir := filepath.Join(policy.GetSystemConfigBasePath(), "policy.d")
	if _, err := p.FileSystem.Stat(pluginsDir); err != nil {
		problems = append(problems, fmt.Sprintf("%s: %v", pluginsDir, err))
		results = append(results, checkResult{Path: pluginsDir, Exists: false, PermsErr: err.Error()})
	} else {
		cr := checkResult{Path: pluginsDir, Exists: true}
		// Check directory perms using plugin package expectations
		if err := p.FileSystem.CheckPerm(pluginsDir, plugins.RequiredPolicyDirPerms(), files.RequiredPerms.PluginsDir.Owner, files.RequiredPerms.PluginsDir.Group); err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", pluginsDir, err))
			cr.PermsErr = err.Error()
		}
		results = append(results, cr)
	}

	if p.JsonOutput {
		enc := json.NewEncoder(p.Out)
		enc.SetIndent("", "  ")
		return enc.Encode(results)
	}

	if len(problems) > 0 {
		for _, prob := range problems {
			fmt.Fprintln(p.Out, "Problem:", prob)
		}
		return fmt.Errorf("permissions check failed: %d problems found", len(problems))
	}
	// Success: print nothing and return nil
	return nil
}

// fixResult is the JSON-serializable result of a permissions fix.
type fixResult struct {
	Planned []string `json:"planned"`
	Errors  []string `json:"errors,omitempty"`
	DryRun  bool     `json:"dryRun"`
}

// Fix attempts to repair permissions/ownership for key paths.
func (p *PermissionsCmd) Fix() error {
	// Planning phase: determine actions without performing them
	var planned []string

	sp := files.RequiredPerms.SystemPolicy
	pv := files.RequiredPerms.Providers
	pld := files.RequiredPerms.PluginsDir
	pf := files.RequiredPerms.PluginFile

	systemPolicy := policy.SystemDefaultPolicyPath
	if _, err := p.FileSystem.Stat(systemPolicy); err != nil {
		planned = append(planned, "create file: "+systemPolicy)
	}
	planned = append(planned, "chmod "+systemPolicy+" to "+sp.Mode.String())
	plannedOwner := sp.Owner
	if sp.Group != "" {
		plannedOwner += ":" + sp.Group
	}
	planned = append(planned, "chown "+systemPolicy+" to "+plannedOwner)

	providersFile := policy.SystemDefaultProvidersPath
	if _, err := p.FileSystem.Stat(providersFile); err == nil {
		planned = append(planned, "chmod "+providersFile+" to "+pv.Mode.String())
		pvOwner := pv.Owner
		if pv.Group != "" {
			pvOwner += ":" + pv.Group
		}
		planned = append(planned, "chown "+providersFile+" to "+pvOwner)
	}

	configFile := filepath.Join(policy.GetSystemConfigBasePath(), "config.yml")
	cp := files.RequiredPerms.Config
	if _, err := p.FileSystem.Stat(configFile); err == nil {
		planned = append(planned, "chmod "+configFile+" to "+cp.Mode.String())
		cpOwner := cp.Owner
		if cp.Group != "" {
			cpOwner += ":" + cp.Group
		}
		planned = append(planned, "chown "+configFile+" to "+cpOwner)
	}

	pluginsDir := filepath.Join(policy.GetSystemConfigBasePath(), "policy.d")
	if _, err := p.FileSystem.Stat(pluginsDir); err != nil {
		planned = append(planned, "mkdir "+pluginsDir)
	}
	// include plugin files if present
	if fi, err := p.FileSystem.Open(pluginsDir); err == nil {
		entries, _ := fi.Readdir(-1)
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".yml") {
				planned = append(planned, fmt.Sprintf("chmod %s to %04o", filepath.Join(pluginsDir, e.Name()), pf.Mode))
				planned = append(planned, "chown "+filepath.Join(pluginsDir, e.Name())+" to "+pf.Owner)
			}
		}
		fi.Close()
	}

	// If dry-run, just print planned actions
	if p.DryRun {
		if p.JsonOutput {
			enc := json.NewEncoder(p.Out)
			enc.SetIndent("", "  ")
			return enc.Encode(fixResult{Planned: planned, DryRun: true})
		}
		for _, a := range planned {
			fmt.Fprintln(p.Out, "Action:", a)
		}
		fmt.Fprintln(p.Out, "dry-run complete")
		return nil
	}

	// Require elevated privileges to perform fixes
	elevated, err := p.IsElevatedFn()
	if err != nil {
		return fmt.Errorf("failed to determine elevation: %w", err)
	}
	if !elevated {
		return fmt.Errorf("fix requires elevated privileges (run as root or Administrator)")
	}

	// Confirm with user unless --yes
	if !p.Yes {
		// show planned actions and ask
		fmt.Fprintln(p.Out, "Planned actions:")
		for _, a := range planned {
			fmt.Fprintln(p.Out, "  -", a)
		}
		ok, err := p.ConfirmPrompt("Apply these changes? [y/N]: ", p.In)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("aborted by user")
		}
	}

	// Execution phase: perform actions
	var errorsFound []string

	// Create system policy file if missing
	if _, err := p.FileSystem.Stat(systemPolicy); err != nil {
		if f, err := p.FileSystem.CreateFile(systemPolicy); err != nil {
			errorsFound = append(errorsFound, "create "+systemPolicy+": "+err.Error())
		} else {
			f.Close()
		}
	}
	if err := p.FileSystem.Chmod(systemPolicy, sp.Mode); err != nil {
		errorsFound = append(errorsFound, "chmod "+systemPolicy+": "+err.Error())
	}
	if err := p.FileSystem.Chown(systemPolicy, sp.Owner, sp.Group); err != nil {
		errorsFound = append(errorsFound, "chown "+systemPolicy+": "+err.Error())
	}

	// Verify ACLs after changes and apply ACE fixes on Windows if needed
	if runtime.GOOS == "windows" {
		expected := files.ExpectedACLFromPerm(sp)
		report, err := p.FileSystem.VerifyACL(systemPolicy, expected)
		if err != nil {
			errorsFound = append(errorsFound, "acl verify: "+err.Error())
		} else {
			for _, reqACE := range expected.RequiredACEs {
				found := false
				for _, a := range report.ACEs {
					if a.Principal == reqACE.Principal && strings.Contains(a.Rights, reqACE.Rights) {
						found = true
						break
					}
				}
				if !found {
					ace := files.ACE{Principal: reqACE.Principal, Rights: reqACE.Rights, Type: reqACE.Type}
					if sid, _, _ := files.ResolveAccountToSID(reqACE.Principal); len(sid) > 0 {
						ace.PrincipalSID = sid
					}
					if err := p.FileSystem.ApplyACE(systemPolicy, ace); err != nil {
						errorsFound = append(errorsFound, fmt.Sprintf("apply ACE %s:%s: %s", reqACE.Principal, reqACE.Rights, err.Error()))
					}
				}
			}
		}
	}

	// Providers file
	if _, err := p.FileSystem.Stat(providersFile); err == nil {
		if err := p.FileSystem.Chmod(providersFile, pv.Mode); err != nil {
			errorsFound = append(errorsFound, "chmod "+providersFile+": "+err.Error())
		}
		if err := p.FileSystem.Chown(providersFile, pv.Owner, pv.Group); err != nil {
			errorsFound = append(errorsFound, "chown "+providersFile+": "+err.Error())
		}
	}

	// Config file
	if _, err := p.FileSystem.Stat(configFile); err == nil {
		if err := p.FileSystem.Chmod(configFile, cp.Mode); err != nil {
			errorsFound = append(errorsFound, "chmod "+configFile+": "+err.Error())
		}
		if err := p.FileSystem.Chown(configFile, cp.Owner, cp.Group); err != nil {
			errorsFound = append(errorsFound, "chown "+configFile+": "+err.Error())
		}
	}

	// Plugins dir
	if _, err := p.FileSystem.Stat(pluginsDir); err != nil {
		if err := p.FileSystem.MkdirAll(pluginsDir, pld.Mode); err != nil {
			errorsFound = append(errorsFound, "mkdir "+pluginsDir+": "+err.Error())
		}
	}
	if fi, err := p.FileSystem.Open(pluginsDir); err == nil {
		entries, _ := fi.Readdir(-1)
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".yml") {
				path := filepath.Join(pluginsDir, e.Name())
				if err := p.FileSystem.Chmod(path, pf.Mode); err != nil {
					errorsFound = append(errorsFound, "chmod "+path+": "+err.Error())
				}
				if err := p.FileSystem.Chown(path, pf.Owner, pf.Group); err != nil {
					errorsFound = append(errorsFound, "chown "+path+": "+err.Error())
				}
				// On Windows, ensure ACLs for plugin files as well
				if runtime.GOOS == "windows" {
					pfExpected := files.ExpectedACLFromPerm(pf)
					if report, err := p.FileSystem.VerifyACL(path, pfExpected); err == nil {
						for _, reqACE := range pfExpected.RequiredACEs {
							found := false
							for _, a := range report.ACEs {
								if a.Principal == reqACE.Principal && strings.Contains(a.Rights, reqACE.Rights) {
									found = true
									break
								}
							}
							if !found {
								ace := files.ACE{Principal: reqACE.Principal, Rights: reqACE.Rights, Type: reqACE.Type}
								if sid, _, _ := files.ResolveAccountToSID(reqACE.Principal); len(sid) > 0 {
									ace.PrincipalSID = sid
								}
								if err := p.FileSystem.ApplyACE(path, ace); err != nil {
									errorsFound = append(errorsFound, fmt.Sprintf("apply ACE %s:%s for %s: %s", reqACE.Principal, reqACE.Rights, path, err.Error()))
								}
							}
						}
					} else {
						errorsFound = append(errorsFound, "acl verify for "+path+": "+err.Error())
					}
				}
			}
		}
		fi.Close()
	}

	if p.JsonOutput {
		enc := json.NewEncoder(p.Out)
		enc.SetIndent("", "  ")
		return enc.Encode(fixResult{Planned: planned, Errors: errorsFound})
	}

	if len(errorsFound) > 0 {
		for _, e := range errorsFound {
			fmt.Fprintln(p.Out, "Error:", e)
		}
		return fmt.Errorf("fix completed with %d errors", len(errorsFound))
	}

	fmt.Fprintln(p.Out, "fix completed successfully")
	return nil
}
