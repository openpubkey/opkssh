//go:build !windows
// +build !windows

package files

import "fmt"

// ConvertSidToString stub for non-Windows platforms.
func ConvertSidToString(sid []byte) (string, error) {
	return "", fmt.Errorf("ConvertSidToString is only supported on Windows")
}
