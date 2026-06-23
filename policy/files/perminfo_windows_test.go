//go:build windows
// +build windows

package files

import (
	"testing"
)

func TestExpectedACLFromPerm_PopulatesRequiredACEs(t *testing.T) {
	pi := PermInfo{
		Mode:  0o640,
		Owner: "Administrators",
		Group: "opksshuser",
	}

	ea := ExpectedACLFromPerm(pi)

	if ea.Owner != "Administrators" {
		t.Fatalf("expected Owner=Administrators, got %q", ea.Owner)
	}
	if ea.Mode != 0o640 {
		t.Fatalf("expected Mode=0o640, got %o", ea.Mode)
	}
	if len(ea.RequiredACEs) != 2 {
		t.Fatalf("expected 2 RequiredACEs, got %d: %+v", len(ea.RequiredACEs), ea.RequiredACEs)
	}

	// First ACE: owner gets GENERIC_ALL
	if ea.RequiredACEs[0].Principal != "Administrators" {
		t.Errorf("RequiredACEs[0].Principal = %q, want Administrators", ea.RequiredACEs[0].Principal)
	}
	if ea.RequiredACEs[0].Rights != "GENERIC_ALL" {
		t.Errorf("RequiredACEs[0].Rights = %q, want GENERIC_ALL", ea.RequiredACEs[0].Rights)
	}
	if ea.RequiredACEs[0].Type != "allow" {
		t.Errorf("RequiredACEs[0].Type = %q, want allow", ea.RequiredACEs[0].Type)
	}

	// Second ACE: group gets GENERIC_READ
	if ea.RequiredACEs[1].Principal != "opksshuser" {
		t.Errorf("RequiredACEs[1].Principal = %q, want opksshuser", ea.RequiredACEs[1].Principal)
	}
	if ea.RequiredACEs[1].Rights != "GENERIC_READ" {
		t.Errorf("RequiredACEs[1].Rights = %q, want GENERIC_READ", ea.RequiredACEs[1].Rights)
	}
	if ea.RequiredACEs[1].Type != "allow" {
		t.Errorf("RequiredACEs[1].Type = %q, want allow", ea.RequiredACEs[1].Type)
	}
}

func TestExpectedACLFromPerm_EmptyGroupNoGroupACE(t *testing.T) {
	pi := PermInfo{
		Mode:  0o600,
		Owner: "Administrators",
		Group: "",
	}

	ea := ExpectedACLFromPerm(pi)

	if len(ea.RequiredACEs) != 1 {
		t.Fatalf("expected 1 RequiredACE (owner only), got %d: %+v", len(ea.RequiredACEs), ea.RequiredACEs)
	}
	if ea.RequiredACEs[0].Principal != "Administrators" {
		t.Errorf("RequiredACEs[0].Principal = %q, want Administrators", ea.RequiredACEs[0].Principal)
	}
}

func TestExpectedACLFromPerm_EmptyOwnerAndGroup(t *testing.T) {
	pi := PermInfo{
		Mode:  0o600,
		Owner: "",
		Group: "",
	}

	ea := ExpectedACLFromPerm(pi)

	if len(ea.RequiredACEs) != 0 {
		t.Fatalf("expected 0 RequiredACEs for empty owner/group, got %d: %+v", len(ea.RequiredACEs), ea.RequiredACEs)
	}
}

func TestRequiredPerms_SystemEntriesHaveOpksshuser(t *testing.T) {
	entries := []struct {
		name string
		pi   PermInfo
	}{
		{"SystemPolicy", RequiredPerms.SystemPolicy},
		{"Providers", RequiredPerms.Providers},
		{"Config", RequiredPerms.Config},
		{"PluginsDir", RequiredPerms.PluginsDir},
		{"PluginFile", RequiredPerms.PluginFile},
	}

	for _, e := range entries {
		t.Run(e.name, func(t *testing.T) {
			if e.pi.Group != "opksshuser" {
				t.Errorf("%s.Group = %q, want opksshuser", e.name, e.pi.Group)
			}
			if e.pi.Owner != "Administrators" {
				t.Errorf("%s.Owner = %q, want Administrators", e.name, e.pi.Owner)
			}
		})
	}
}

func TestRequiredPerms_HomePolicyHasNoGroup(t *testing.T) {
	if RequiredPerms.HomePolicy.Group != "" {
		t.Errorf("HomePolicy.Group = %q, want empty", RequiredPerms.HomePolicy.Group)
	}
}
