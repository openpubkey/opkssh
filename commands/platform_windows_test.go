//go:build windows
// +build windows

package commands

import "testing"

func TestExpectedSystemOwner_Windows(t *testing.T) {
	if expectedSystemOwner() != "Administrators" {
		t.Fatalf("expected Administrators on Windows, got %q", expectedSystemOwner())
	}
}
