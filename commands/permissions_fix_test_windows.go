//go:build windows
// +build windows

package commands

import (
	"io/fs"
	"testing"

	"github.com/openpubkey/opkssh/policy"
	"github.com/openpubkey/opkssh/policy/files"
	"github.com/spf13/afero"
)

type mockOps struct {
	Fs      afero.Fs
	Applied []files.ACE
}

func (m *mockOps) MkdirAllWithPerm(path string, perm fs.FileMode) error {
	return m.Fs.MkdirAll(path, 0750)
}
func (m *mockOps) CreateFileWithPerm(path string) (afero.File, error) { return m.Fs.Create(path) }
func (m *mockOps) WriteFileWithPerm(path string, data []byte, perm fs.FileMode) error {
	return afero.WriteFile(m.Fs, path, data, 0644)
}
func (m *mockOps) Chmod(path string, perm fs.FileMode) error           { return m.Fs.Chmod(path, 0644) }
func (m *mockOps) Stat(path string) (fs.FileInfo, error)               { return m.Fs.Stat(path) }
func (m *mockOps) Chown(path string, owner string, group string) error { return nil }
func (m *mockOps) ApplyACE(path string, ace files.ACE) error {
	m.Applied = append(m.Applied, ace)
	return nil
}

type mockVerifier struct {
	Report files.ACLReport
}

func (m *mockVerifier) VerifyACL(path string, expected files.ExpectedACL) (files.ACLReport, error) {
	return m.Report, nil
}

func TestRunPermissionsFix_AppliesAdminACE_Windows(t *testing.T) {
	// Setup in-memory fs with system policy file
	mem := afero.NewMemMapFs()
	systemPolicy := policy.SystemDefaultPolicyPath
	afero.WriteFile(mem, systemPolicy, []byte("x"), 0644)
	// ensure plugins dir exists but no ACEs present
	pluginsDir := policy.GetSystemConfigBasePath() + "/policy.d"
	mem.MkdirAll(pluginsDir, 0750)
	afero.WriteFile(mem, pluginsDir+"/plugin.yml", []byte("a"), 0644)

	mops := &mockOps{Fs: mem}
	// Verifier returns no ACEs so ApplyACE should be called for Admin and SYSTEM
	mv := &mockVerifier{Report: files.ACLReport{Path: systemPolicy, Exists: true, ACEs: []files.ACE{}}}

	// Force elevation success
	prev := IsElevatedFunc
	IsElevatedFunc = func() (bool, error) { return true, nil }
	defer func() { IsElevatedFunc = prev }()

	err := runPermissionsFixWithDeps(mops, mv, mem, false, true, false)
	if err != nil {
		t.Fatalf("runPermissionsFixWithDeps failed: %v", err)
	}

	if len(mops.Applied) < 2 {
		t.Fatalf("expected at least 2 ApplyACE calls for Admin and SYSTEM, got %d", len(mops.Applied))
	}

	// check principals present
	var foundAdmin, foundSystem bool
	for _, a := range mops.Applied {
		if a.Principal == "Administrators" {
			foundAdmin = true
		}
		if a.Principal == "SYSTEM" {
			foundSystem = true
		}
	}
	if !foundAdmin || !foundSystem {
		t.Fatalf("expected ApplyACE for Administrators and SYSTEM, got: %+v", mops.Applied)
	}
}
