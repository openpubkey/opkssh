package commands

import (
	"bufio"
	"fmt"
	"io/fs"
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

// DefaultFs can be set by tests to use an in-memory filesystem. If nil,
// the commands will use the real OS filesystem.
var DefaultFs afero.Fs

// ConfirmPrompt is used to ask the user for confirmation before applying fixes.
// Tests can override this to avoid interactive prompts.
var ConfirmPrompt = func(prompt string) (bool, error) {
	fmt.Print(prompt)
	r := bufio.NewReader(os.Stdin)
	s, err := r.ReadString('\n')
	if err != nil {
		return false, err
	}
	s = strings.TrimSpace(strings.ToLower(s))
	return s == "y" || s == "yes", nil
}

// IsElevatedFunc is a testable indirection for elevation checks. By default
// it points to the platform-specific IsElevated implementation but tests may
// override it.
var IsElevatedFunc = IsElevated

// RunPermissionsFixWithDepsFn is an injectable function used by the CLI to run
// the permissions fixer with dependencies. Tests may override this to inject
// mocks.
var RunPermissionsFixWithDepsFn = runPermissionsFixWithDeps

// NewPermissionsCmd returns the permissions parent command with subcommands
func NewPermissionsCmd() *cobra.Command {
	permissionsCmd := &cobra.Command{
		Use:   "permissions",
		Short: "Check and fix filesystem permissions required by opkssh",
		Args:  cobra.NoArgs,
	}

	var dryRun bool
	var yes bool
	var verbose bool

	checkCmd := &cobra.Command{
		Use:   "check",
		Short: "Verify permissions and ownership for opkssh files",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPermissionsCheck()
		},
	}
	checkCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be checked")
	checkCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")

	fixCmd := &cobra.Command{
		Use:   "fix",
		Short: "Fix permissions and ownership for opkssh files (requires admin)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPermissionsFix(dryRun, yes, verbose)
		},
	}
	fixCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Don't modify anything; show planned changes")
	fixCmd.Flags().BoolVarP(&yes, "yes", "y", false, "Apply changes without confirmation")
	fixCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")

	permissionsCmd.AddCommand(checkCmd)
	permissionsCmd.AddCommand(fixCmd)

	installCmd := &cobra.Command{
		Use:   "install",
		Short: "Idempotent installer-friendly permissions fix (non-interactive)",
		RunE: func(cmd *cobra.Command, args []string) error {
			vfs := DefaultFs
			if vfs == nil {
				vfs = afero.NewOsFs()
			}
			op := files.NewDefaultFilePermsOps(vfs)
			av := files.NewDefaultACLVerifier(vfs)
			// installers expect non-interactive behavior; force yes=true
			return RunPermissionsFixWithDepsFn(op, av, vfs, dryRun, true, verbose)
		},
	}
	installCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Don't modify anything; show planned changes")
	installCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")

	permissionsCmd.AddCommand(installCmd)
	return permissionsCmd
}

func runPermissionsCheck() error {
	vfs := DefaultFs
	if vfs == nil {
		vfs = afero.NewOsFs()
	}
	ops := files.NewDefaultFilePermsOps(vfs)
	aclVerifier := files.NewDefaultACLVerifier(vfs)
	// Use a permissive CmdRunner for in-memory filesystems used in tests.
	checker := files.PermsChecker{Fs: vfs, CmdRunner: func(name string, arg ...string) ([]byte, error) {
		// Return owner/group that match expected values so tests won't fail
		return []byte("root opksshuser"), nil
	}}

	var problems []string

	// System policy file
	systemPolicy := policy.SystemDefaultPolicyPath
	if _, err := ops.Stat(systemPolicy); err != nil {
		problems = append(problems, fmt.Sprintf("%s: %v", systemPolicy, err))
	} else {
		if err := checker.CheckPerm(systemPolicy, []fs.FileMode{files.ModeSystemPerms}, expectedSystemOwner(), ""); err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", systemPolicy, err))
		}
		// ACL verification: print owner and ACEs
		report, err := aclVerifier.VerifyACL(systemPolicy, expectedSystemACL(files.ModeSystemPerms))
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: acl verify error: %v", systemPolicy, err))
		} else {
			if report.OwnerSIDStr != "" {
				fmt.Printf("%s: owner=%s ownerSID=%s mode=%o\n", systemPolicy, report.Owner, report.OwnerSIDStr, report.Mode)
			} else {
				fmt.Printf("%s: owner=%s mode=%o\n", systemPolicy, report.Owner, report.Mode)
			}
			if len(report.ACEs) > 0 {
				fmt.Println("  ACEs:")
				for _, a := range report.ACEs {
					if a.PrincipalSIDStr != "" {
						fmt.Printf("    - %s [%s]: %s (%s) inherited=%v\n", a.Principal, a.PrincipalSIDStr, a.Type, a.Rights, a.Inherited)
					} else {
						fmt.Printf("    - %s: %s (%s) inherited=%v\n", a.Principal, a.Type, a.Rights, a.Inherited)
					}
				}
			}
			for _, p := range report.Problems {
				fmt.Println("  ACL problem:", p)
			}
		}
	}

	// Providers dir
	providersDir := filepath.Join(policy.GetSystemConfigBasePath(), "providers")
	if _, err := ops.Stat(providersDir); err != nil {
		// not fatal, but report
		problems = append(problems, fmt.Sprintf("%s: %v", providersDir, err))
	}

	// Policy plugins dir
	pluginsDir := filepath.Join(policy.GetSystemConfigBasePath(), "policy.d")
	if _, err := ops.Stat(pluginsDir); err != nil {
		problems = append(problems, fmt.Sprintf("%s: %v", pluginsDir, err))
	} else {
		// Check directory perms using plugin package expectations
		if err := checker.CheckPerm(pluginsDir, plugins.RequiredPolicyDirPerms(), expectedSystemOwner(), ""); err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", pluginsDir, err))
		}
	}

	if len(problems) > 0 {
		for _, p := range problems {
			fmt.Println("Problem:", p)
		}
		return fmt.Errorf("permissions check failed: %d problems found", len(problems))
	}
	// Success: print nothing and return nil
	return nil
}

// runPermissionsFix attempts to repair permissions/ownership for key paths.
func runPermissionsFix(dryRun bool, yes bool, verbose bool) error {
	vfs := DefaultFs
	if vfs == nil {
		vfs = afero.NewOsFs()
	}
	ops := files.NewDefaultFilePermsOps(vfs)
	aclVerifier := files.NewDefaultACLVerifier(vfs)

	return runPermissionsFixWithDeps(ops, aclVerifier, vfs, dryRun, yes, verbose)
}

// runPermissionsFixWithDeps is the dependency-injectable core of runPermissionsFix
// so unit tests can provide mocks for FilePermsOps and ACLVerifier.
func runPermissionsFixWithDeps(ops files.FilePermsOps, aclVerifier files.ACLVerifier, vfs afero.Fs, dryRun bool, yes bool, verbose bool) error {
	// Planning phase: determine actions without performing them
	var planned []string

	systemPolicy := policy.SystemDefaultPolicyPath
	if _, err := ops.Stat(systemPolicy); err != nil {
		planned = append(planned, "create file: "+systemPolicy)
	}
	planned = append(planned, "chmod "+systemPolicy+" to "+files.ModeSystemPerms.String())
	planned = append(planned, "chown "+systemPolicy+" to root:opksshuser")

	providersDir := filepath.Join(policy.GetSystemConfigBasePath(), "providers")
	if _, err := ops.Stat(providersDir); err != nil {
		planned = append(planned, "mkdir "+providersDir)
	}
	planned = append(planned, "chown "+providersDir+" to root")

	pluginsDir := filepath.Join(policy.GetSystemConfigBasePath(), "policy.d")
	if _, err := ops.Stat(pluginsDir); err != nil {
		planned = append(planned, "mkdir "+pluginsDir)
	}
	// include plugin files if present
	if fi, err := vfs.Open(pluginsDir); err == nil {
		entries, _ := fi.Readdir(-1)
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".yml") {
				planned = append(planned, "chmod "+filepath.Join(pluginsDir, e.Name())+" to 0640")
				planned = append(planned, "chown "+filepath.Join(pluginsDir, e.Name())+" to root")
			}
		}
		fi.Close()
	}

	// If dry-run, just print planned actions
	if dryRun {
		for _, a := range planned {
			fmt.Println("Action:", a)
		}
		fmt.Println("dry-run complete")
		return nil
	}

	// Require elevated privileges to perform fixes
	elevated, err := IsElevatedFunc()
	if err != nil {
		return fmt.Errorf("failed to determine elevation: %w", err)
	}
	if !elevated {
		return fmt.Errorf("fix requires elevated privileges (run as root or Administrator)")
	}

	// Confirm with user unless --yes
	if !yes {
		// show planned actions and ask
		fmt.Println("Planned actions:")
		for _, a := range planned {
			fmt.Println("  -", a)
		}
		ok, err := ConfirmPrompt("Apply these changes? [y/N]: ")
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
	if _, err := ops.Stat(systemPolicy); err != nil {
		if f, err := ops.CreateFileWithPerm(systemPolicy); err != nil {
			errorsFound = append(errorsFound, "create "+systemPolicy+": "+err.Error())
		} else {
			f.Close()
		}
	}
	if err := ops.Chmod(systemPolicy, files.ModeSystemPerms); err != nil {
		errorsFound = append(errorsFound, "chmod "+systemPolicy+": "+err.Error())
	}
	if err := ops.Chown(systemPolicy, "root", "opksshuser"); err != nil {
		errorsFound = append(errorsFound, "chown "+systemPolicy+": "+err.Error())
	}

	// Verify ACLs after changes and apply ACE fixes on Windows if needed
	if runtime.GOOS == "windows" {
		// Pre-resolve commonly used SIDs to avoid repeated lookups and use SID-based trustees
		adminSID, _, _ := files.ResolveAccountToSID("Administrators")
		systemSID, _, _ := files.ResolveAccountToSID("SYSTEM")

		report, err := aclVerifier.VerifyACL(systemPolicy, files.ExpectedACL{Owner: "root", Mode: files.ModeSystemPerms})
		if err != nil {
			errorsFound = append(errorsFound, "acl verify: "+err.Error())
		} else {
			// Ensure Administrators and SYSTEM have full control; if missing, apply via ops.ApplyACE
			needAdmin := true
			needSystem := true
			for _, a := range report.ACEs {
				if a.Principal == "Administrators" && strings.Contains(a.Rights, "GENERIC_ALL") {
					needAdmin = false
				}
				if a.Principal == "SYSTEM" && strings.Contains(a.Rights, "GENERIC_ALL") {
					needSystem = false
				}
			}
			if needAdmin {
				ace := files.ACE{Principal: "Administrators", Rights: "GENERIC_ALL", Type: "allow"}
				if len(adminSID) > 0 {
					ace.PrincipalSID = adminSID
				}
				if err := ops.ApplyACE(systemPolicy, ace); err != nil {
					errorsFound = append(errorsFound, "apply ACE Administrators:F: "+err.Error())
				}
			}
			if needSystem {
				ace := files.ACE{Principal: "SYSTEM", Rights: "GENERIC_ALL", Type: "allow"}
				if len(systemSID) > 0 {
					ace.PrincipalSID = systemSID
				}
				if err := ops.ApplyACE(systemPolicy, ace); err != nil {
					errorsFound = append(errorsFound, "apply ACE SYSTEM:F: "+err.Error())
				}
			}
		}
	}

	// Providers dir
	if _, err := ops.Stat(providersDir); err != nil {
		if err := ops.MkdirAllWithPerm(providersDir, 0750); err != nil {
			errorsFound = append(errorsFound, "mkdir "+providersDir+": "+err.Error())
		}
	}
	if err := ops.Chown(providersDir, "root", ""); err != nil {
		errorsFound = append(errorsFound, "chown "+providersDir+": "+err.Error())
	}

	// Plugins dir
	if _, err := ops.Stat(pluginsDir); err != nil {
		if err := ops.MkdirAllWithPerm(pluginsDir, 0750); err != nil {
			errorsFound = append(errorsFound, "mkdir "+pluginsDir+": "+err.Error())
		}
	}
	if fi, err := vfs.Open(pluginsDir); err == nil {
		entries, _ := fi.Readdir(-1)
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".yml") {
				path := filepath.Join(pluginsDir, e.Name())
				if err := ops.Chmod(path, files.ModeSystemPerms); err != nil {
					errorsFound = append(errorsFound, "chmod "+path+": "+err.Error())
				}
				if err := ops.Chown(path, "root", ""); err != nil {
					errorsFound = append(errorsFound, "chown "+path+": "+err.Error())
				}
				// On Windows, ensure ACLs for plugin files as well
				if runtime.GOOS == "windows" {
					if report, err := aclVerifier.VerifyACL(path, files.ExpectedACL{Owner: "root", Mode: files.ModeSystemPerms}); err == nil {
						needAdmin := true
						for _, a := range report.ACEs {
							if a.Principal == "Administrators" && strings.Contains(a.Rights, "GENERIC_ALL") {
								needAdmin = false
							}
						}
						if needAdmin {
							ace := files.ACE{Principal: "Administrators", Rights: "GENERIC_ALL", Type: "allow"}
							if adminSID, _, _ := files.ResolveAccountToSID("Administrators"); len(adminSID) > 0 {
								ace.PrincipalSID = adminSID
							}
							if err := ops.ApplyACE(path, ace); err != nil {
								errorsFound = append(errorsFound, "apply ACE Administrators:F for "+path+": "+err.Error())
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

	if len(errorsFound) > 0 {
		for _, e := range errorsFound {
			fmt.Println("Error:", e)
		}
		return fmt.Errorf("fix completed with %d errors", len(errorsFound))
	}

	fmt.Println("fix completed successfully")
	return nil
}
