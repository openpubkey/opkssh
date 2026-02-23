//go:build !windows
// +build !windows

package files

import "fmt"

// ResolveAccountToSID is a stub on non-Windows platforms.
func ResolveAccountToSID(name string) ([]byte, uint32, error) {
	return nil, 0, fmt.Errorf("ResolveAccountToSID is only supported on Windows")
}
