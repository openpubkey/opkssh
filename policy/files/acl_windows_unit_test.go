//go:build windows
// +build windows

package files

import (
	"strings"
	"testing"
)

// Test that maskToRights returns expected tokens for some common masks.
func TestMaskToRights_Common(t *testing.T) {
	m := uint32(0x80000000) // GENERIC_READ
	s := maskToRights(m)
	if !strings.Contains(s, "GENERIC_READ") {
		t.Fatalf("expected GENERIC_READ in %q", s)
	}

	m = 0x10000000 // GENERIC_ALL
	s = maskToRights(m)
	if !strings.Contains(s, "GENERIC_ALL") {
		t.Fatalf("expected GENERIC_ALL in %q", s)
	}
}

// Test resolving a well-known account and converting to textual SID.
func TestResolveAndConvertAdministratorsSID(t *testing.T) {
	sid, _, err := ResolveAccountToSID("Administrators")
	if err != nil {
		t.Fatalf("ResolveAccountToSID failed: %v", err)
	}
	if len(sid) == 0 {
		t.Fatalf("empty SID returned")
	}
	s, err := ConvertSidToString(sid)
	if err != nil {
		t.Fatalf("ConvertSidToString failed: %v", err)
	}
	if len(s) < 2 || s[:2] != "S-" {
		t.Fatalf("unexpected SID string: %q", s)
	}
}
