//go:build !windows
// +build !windows

package files

import "testing"

func TestMaskToRights_SkippedOnNonWindows(t *testing.T) {
	t.Skip("Windows-specific ACL mask tests are skipped on non-Windows platforms")
}
