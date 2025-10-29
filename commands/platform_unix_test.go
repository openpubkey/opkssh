//go:build !windows
// +build !windows

package commands

import "testing"

func TestExpectedSystemOwner_Unix(t *testing.T) {
	if expectedSystemOwner() != "root" {
		t.Fatalf("expected root on non-Windows, got %q", expectedSystemOwner())
	}
}
