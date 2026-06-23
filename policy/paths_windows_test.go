//go:build windows
// +build windows

package policy

import (
	"path/filepath"
	"testing"
)

func TestSystemDefaultProvidersPath_Windows(t *testing.T) {
	expected := filepath.Join(GetSystemConfigBasePath(), "providers")
	if SystemDefaultProvidersPath != expected {
		t.Fatalf("expected SystemDefaultProvidersPath %q, got %q", expected, SystemDefaultProvidersPath)
	}
}
