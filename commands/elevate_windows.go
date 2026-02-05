//go:build windows
// +build windows

package commands

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// IsElevated returns true if the current process token indicates elevation on Windows.
func IsElevated() (bool, error) {
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
	if err != nil {
		return false, err
	}
	defer token.Close()

	var elevation uint32
	var retLen uint32
	err = windows.GetTokenInformation(token, windows.TokenElevation, (*byte)(unsafe.Pointer(&elevation)), uint32(unsafe.Sizeof(elevation)), &retLen)
	if err != nil {
		return false, err
	}
	return elevation != 0, nil
}
