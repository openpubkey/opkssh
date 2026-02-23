//go:build !windows
// +build !windows

package commands

import "os"

// IsElevated returns true if the current process is running as root on Unix-like systems.
func IsElevated() (bool, error) {
	return os.Geteuid() == 0, nil
}
