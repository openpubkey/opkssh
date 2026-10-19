package commands

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"testing"

	"github.com/openpubkey/opkssh/policy"
	"github.com/openpubkey/opkssh/policy/files"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

func TestPermissionsCheck_MissingSystemPolicyReportsProblem(t *testing.T) {
	vfs := afero.NewMemMapFs()
	out := &bytes.Buffer{}
	p := newTestPermissionsCmd(vfs, out)

	// No system policy file created -> check should report problems
	err := p.Check()
	require.Error(t, err)
}

func TestPermissionsCheck_WithSystemPolicyAndPlugins_Succeeds(t *testing.T) {
	vfs := afero.NewMemMapFs()
	out := &bytes.Buffer{}
	p := newTestPermissionsCmd(vfs, out)

	// Create system policy file and parents under the system config base
	path := policy.SystemDefaultPolicyPath
	base := policy.GetSystemConfigBasePath()
	_ = vfs.MkdirAll(base, 0o750)
	err := afero.WriteFile(vfs, path, []byte("user1 alice@example.com google\n"), 0o640)
	require.NoError(t, err)

	// Create providers file and plugins dir
	providersFile := filepath.Join(base, "providers")
	err = afero.WriteFile(vfs, providersFile, []byte("https://accounts.google.com google-client-id 24h\n"), 0o640)
	require.NoError(t, err)
	pluginsDir := filepath.Join(base, "policy.d")
	_ = vfs.MkdirAll(pluginsDir, 0o750)
	err = afero.WriteFile(vfs, filepath.Join(pluginsDir, "example.yml"), []byte("name: test\ncommand: /bin/true\n"), 0o640)
	require.NoError(t, err)

	err = p.Check()
	require.NoError(t, err)
}

func TestPermissionsFix_DryRun_NoPanic(t *testing.T) {
	vfs := afero.NewMemMapFs()
	out := &bytes.Buffer{}
	p := newTestPermissionsCmd(vfs, out)
	p.DryRun = true
	p.Verbose = true

	// Dry-run should not attempt to change real FS and should return nil
	err := p.Fix()
	require.NoError(t, err)
}

// newTestPermissionsCmdSplit is newTestPermissionsCmd with stdout and stderr
// kept apart, so a test can assert what lands on stdout on its own.
func newTestPermissionsCmdSplit(vfs afero.Fs, out io.Writer, errOut io.Writer) *PermissionsCmd {
	p := newTestPermissionsCmd(vfs, out)
	p.ErrOut = errOut
	return p
}

// writeCheckableConfig lays down a system policy file and a providers file
// with the permissions Check expects, and deliberately leaves out the policy
// plugin directory so that Check has a problem to report.
func writeCheckableConfig(t *testing.T, vfs afero.Fs) {
	t.Helper()
	base := policy.GetSystemConfigBasePath()
	require.NoError(t, vfs.MkdirAll(base, 0o750))
	require.NoError(t, afero.WriteFile(vfs, policy.SystemDefaultPolicyPath,
		[]byte("user1 alice@example.com google\n"), 0o640))
	require.NoError(t, afero.WriteFile(vfs, filepath.Join(base, "providers"),
		[]byte("https://accounts.google.com google-client-id 24h\n"), 0o640))
}

// requireSingleJSONDocument decodes stdOut strictly into v and fails unless
// it holds exactly one JSON document and nothing else.
func requireSingleJSONDocument(t *testing.T, stdOut *bytes.Buffer, v any) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(stdOut.Bytes()))
	decoder.DisallowUnknownFields()
	require.NoError(t, decoder.Decode(v), "Expected stdOut to be valid JSON:\n%s", stdOut.String())
	require.False(t, decoder.More(), "Expected nothing after the JSON document on stdOut:\n%s", stdOut.String())
}

// runPermissionsCobra runs the permissions command tree the way main does,
// so the --json flag wiring is exercised too.
func runPermissionsCobra(p *PermissionsCmd, args ...string) error {
	cmd := p.CobraCommand()
	cmd.SetArgs(args)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SilenceUsage = true
	return cmd.Execute()
}

// In JSON mode stdout must be exactly one JSON document, so that
// `opkssh permissions check --json 2>/dev/null` can be piped to a parser,
// the same contract audit --json already keeps.
func TestPermissionsCheck_JsonOutputIsParseable(t *testing.T) {
	vfs := afero.NewMemMapFs()
	writeCheckableConfig(t, vfs)

	stdOut := &bytes.Buffer{}
	p := newTestPermissionsCmdSplit(vfs, stdOut, &bytes.Buffer{})
	p.FileSystem.(*ownerStubFileSystem).aclProblems = map[string][]string{
		policy.SystemDefaultPolicyPath: {"expected owner (root), got (alice)"},
	}

	require.Error(t, runPermissionsCobra(p, "check", "--json"))

	var parsed checkReport
	requireSingleJSONDocument(t, stdOut, &parsed)
	require.False(t, parsed.Ok)
	require.Contains(t, parsed.Problems, policy.SystemDefaultPolicyPath+": acl: expected owner (root), got (alice)")
	require.Equal(t, policy.SystemDefaultPolicyPath, parsed.Files[0].Path)
	require.Equal(t, []string{"expected owner (root), got (alice)"}, parsed.Files[0].ACLProblems)
}

// The JSON key names are part of the output contract; they are snake_case
// like audit --json.
func TestPermissionsCheck_JsonShape(t *testing.T) {
	vfs := afero.NewMemMapFs()
	writeCompleteConfig(t, vfs)

	stdOut := &bytes.Buffer{}
	p := newTestPermissionsCmdSplit(vfs, stdOut, &bytes.Buffer{})
	stub := p.FileSystem.(*ownerStubFileSystem)
	stub.permErrors = map[string]error{
		policy.SystemDefaultProvidersPath: errors.New("expected one of the following permissions [640], got (644)"),
	}
	stub.aclProblems = map[string][]string{
		policy.SystemDefaultProvidersPath: {"expected mode 640, got 644"},
	}
	require.Error(t, runPermissionsCobra(p, "check", "--json"))

	providers := policy.SystemDefaultProvidersPath
	policyD := filepath.Join(policy.GetSystemConfigBasePath(), "policy.d")
	require.JSONEq(t, fmt.Sprintf(`{
		"ok": false,
		"problems": [%[2]q],
		"files": [
			{"path": %[1]q, "exists": true},
			{"path": %[3]q, "exists": true, "perms_error": %[4]q, "acl_problems": ["expected mode 640, got 644"]},
			{"path": %[5]q, "exists": true}
		]
	}`, policy.SystemDefaultPolicyPath,
		providers+": expected one of the following permissions [640], got (644)",
		providers, "expected one of the following permissions [640], got (644)", policyD),
		stdOut.String())
}

// A passing check reports ok and an empty problems list, not null.
func TestPermissionsCheck_JsonPassingCheck(t *testing.T) {
	vfs := afero.NewMemMapFs()
	writeCompleteConfig(t, vfs)

	stdOut := &bytes.Buffer{}
	p := newTestPermissionsCmdSplit(vfs, stdOut, &bytes.Buffer{})
	require.NoError(t, runPermissionsCobra(p, "check", "--json"))

	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(stdOut.Bytes(), &raw))
	require.JSONEq(t, `true`, string(raw["ok"]))
	require.JSONEq(t, `[]`, string(raw["problems"]))
}

// writeCompleteConfig lays down every file and directory Check expects, with
// the expected permissions, so that a check of it passes.
func writeCompleteConfig(t *testing.T, vfs afero.Fs) {
	t.Helper()
	writeCheckableConfig(t, vfs)
	require.NoError(t, vfs.MkdirAll(filepath.Join(policy.GetSystemConfigBasePath(), "policy.d"), 0o750))
}

// An ACL problem on its own fails the check, in text and in JSON mode.
func TestPermissionsCheck_ACLProblemFailsCheck(t *testing.T) {
	for _, jsonOutput := range []bool{false, true} {
		t.Run(fmt.Sprintf("json=%v", jsonOutput), func(t *testing.T) {
			vfs := afero.NewMemMapFs()
			writeCompleteConfig(t, vfs)

			// Control: the same configuration passes without the ACL problem.
			require.NoError(t, newTestPermissionsCmd(vfs, &bytes.Buffer{}).Check())

			stdOut := &bytes.Buffer{}
			p := newTestPermissionsCmdSplit(vfs, stdOut, &bytes.Buffer{})
			p.JsonOutput = jsonOutput
			p.FileSystem.(*ownerStubFileSystem).aclProblems = map[string][]string{
				policy.SystemDefaultProvidersPath: {"expected owner (root), got (alice)"},
			}

			err := p.Check()
			require.EqualError(t, err, "permissions check failed: 1 problems found")
			if !jsonOutput {
				require.Contains(t, stdOut.String(),
					"Problem: "+policy.SystemDefaultProvidersPath+": acl: expected owner (root), got (alice)")
			}
		})
	}
}

// fixTestCmd returns a PermissionsCmd for fix tests whose stdout and stderr
// are kept apart.
func fixTestCmd(t *testing.T, stdOut, errOut *bytes.Buffer) *PermissionsCmd {
	t.Helper()
	vfs := afero.NewMemMapFs()
	writeCheckableConfig(t, vfs)
	return newTestPermissionsCmdSplit(vfs, stdOut, errOut)
}

// A successful fix in JSON mode prints only the JSON result on stdout.
func TestPermissionsFix_JsonOutputIsParseable(t *testing.T) {
	stdOut, errOut := &bytes.Buffer{}, &bytes.Buffer{}
	p := fixTestCmd(t, stdOut, errOut)

	require.NoError(t, runPermissionsCobra(p, "fix", "--json", "--yes"))

	var parsed fixResult
	requireSingleJSONDocument(t, stdOut, &parsed)
	require.NotEmpty(t, parsed.Planned)
	require.Empty(t, parsed.Errors)
}

// fix --json can't prompt, so it needs --yes or --dry-run, as terraform apply
// -json needs -auto-approve. It refuses before planning or changing anything.
func TestPermissionsFix_JsonRequiresYesOrDryRun(t *testing.T) {
	stdOut, errOut := &bytes.Buffer{}, &bytes.Buffer{}
	p := fixTestCmd(t, stdOut, errOut)
	p.ConfirmPrompt = func(prompt string, in io.Reader) (bool, error) {
		t.Fatal("fix --json must not prompt")
		return false, nil
	}
	p.IsElevatedFn = func() (bool, error) {
		t.Fatal("fix --json without --yes must stop before the elevation check")
		return false, nil
	}

	require.ErrorIs(t, runPermissionsCobra(p, "fix", "--json"), errJsonNeedsYes)
	require.Empty(t, stdOut.String())
}

// --dry-run is enough for fix --json: nothing is changed, so nothing to confirm.
func TestPermissionsFix_JsonDryRunNeedsNoYes(t *testing.T) {
	stdOut := &bytes.Buffer{}
	p := fixTestCmd(t, stdOut, &bytes.Buffer{})

	require.NoError(t, runPermissionsCobra(p, "fix", "--json", "--dry-run"))

	var parsed fixResult
	requireSingleJSONDocument(t, stdOut, &parsed)
	require.True(t, parsed.DryRun)
	require.Contains(t, stdOut.String(), `"dry_run": true`)
}

// A file with a wrong mode counts as one problem, even though the ACL
// verifier also reports the mode.
func TestPermissionsCheck_PermsErrAndACLProblemCountOnce(t *testing.T) {
	vfs := afero.NewMemMapFs()
	writeCompleteConfig(t, vfs)

	stdOut := &bytes.Buffer{}
	p := newTestPermissionsCmdSplit(vfs, stdOut, &bytes.Buffer{})
	p.JsonOutput = true
	stub := p.FileSystem.(*ownerStubFileSystem)
	stub.permErrors = map[string]error{
		policy.SystemDefaultProvidersPath: errors.New("expected one of the following permissions [640], got (644)"),
	}
	stub.aclProblems = map[string][]string{
		policy.SystemDefaultProvidersPath: {"expected mode 640, got 644"},
	}

	require.EqualError(t, p.Check(), "permissions check failed: 1 problems found")
	var parsed checkReport
	requireSingleJSONDocument(t, stdOut, &parsed)
	require.Equal(t, policy.SystemDefaultProvidersPath, parsed.Files[1].Path)
	require.NotEmpty(t, parsed.Files[1].PermsErr)
	require.Equal(t, []string{"expected mode 640, got 644"}, parsed.Files[1].ACLProblems)
}

// A failed check must exit non-zero whichever output format was asked for.
func TestPermissionsCheck_JsonOutputStillReportsFailure(t *testing.T) {
	vfs := afero.NewMemMapFs()
	writeCheckableConfig(t, vfs)

	// Positive control: the same configuration is a failing one in text mode,
	// so a nil error below is the reporting bug and not an empty scenario.
	textOut := &bytes.Buffer{}
	textCmd := newTestPermissionsCmdSplit(vfs, textOut, &bytes.Buffer{})
	require.Error(t, textCmd.Check(), "test setup should produce a failing check")

	stdOut := &bytes.Buffer{}
	p := newTestPermissionsCmdSplit(vfs, stdOut, &bytes.Buffer{})
	p.JsonOutput = true
	require.Error(t, p.Check())
}

// The same contract applies to fix: a run that could not apply every change
// must exit non-zero in JSON mode too.
func TestPermissionsFix_JsonOutputStillReportsFailure(t *testing.T) {
	vfs := afero.NewMemMapFs()
	writeCheckableConfig(t, vfs)

	fsys := &chownFailingFileSystem{FileSystem: files.NewFileSystem(vfs,
		files.WithCmdRunner(func(name string, arg ...string) ([]byte, error) {
			return []byte("root opksshuser"), nil
		}))}

	newCmd := func() *PermissionsCmd {
		return &PermissionsCmd{
			FileSystem:    fsys,
			Out:           &bytes.Buffer{},
			ErrOut:        &bytes.Buffer{},
			IsElevatedFn:  func() (bool, error) { return true, nil },
			ConfirmPrompt: func(prompt string, in io.Reader) (bool, error) { return true, nil },
			Yes:           true,
		}
	}

	// Positive control: text mode reports the chown failures.
	require.Error(t, newCmd().Fix(), "test setup should produce a failing fix")

	jsonCmd := newCmd()
	jsonCmd.JsonOutput = true
	require.Error(t, jsonCmd.Fix())
}

// chownFailingFileSystem makes every Chown fail so Fix collects errors.
type chownFailingFileSystem struct {
	files.FileSystem
}

func (c *chownFailingFileSystem) Chown(path string, owner string, group string) error {
	return fmt.Errorf("chown not permitted in test")
}
