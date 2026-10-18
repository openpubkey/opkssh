package commands

import (
	"bytes"
	"encoding/json"
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

// In JSON mode stdout must be exactly one JSON document, so that
// `opkssh permissions check --json 2>/dev/null` can be piped to a parser,
// the same contract audit --json already keeps.
func TestPermissionsCheck_JsonOutputIsParseable(t *testing.T) {
	vfs := afero.NewMemMapFs()
	writeCheckableConfig(t, vfs)

	stdOut := &bytes.Buffer{}
	errOut := &bytes.Buffer{}
	p := newTestPermissionsCmdSplit(vfs, stdOut, errOut)
	p.JsonOutput = true

	_ = p.Check()

	var parsed []checkResult
	decoder := json.NewDecoder(bytes.NewReader(stdOut.Bytes()))
	decoder.DisallowUnknownFields()
	require.NoError(t, decoder.Decode(&parsed), "Expected stdOut to be valid JSON:\n%s", stdOut.String())
	require.False(t, decoder.More(), "Expected nothing after the JSON document on stdOut:\n%s", stdOut.String())
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
