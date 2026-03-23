//go:build windows
// +build windows

package files

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procLookupAccountName = advapi32.NewProc("LookupAccountNameW")
var procConvertSidToString = advapi32.NewProc("ConvertSidToStringSidW")

// ResolveAccountToSID resolves an account name (e.g. "Administrators") to a
// raw SID byte slice and returns the SID_NAME_USE (sidUse) value. Returns an
// error if resolution fails.
func ResolveAccountToSID(name string) ([]byte, uint32, error) {
	if name == "" {
		return nil, 0, fmt.Errorf("empty name")
	}
	pName, _ := syscall.UTF16PtrFromString(name)
	var sidSize uint32
	var domSize uint32
	var sidUse uint32
	// first call to determine sizes
	procLookupAccountName.Call(
		0,
		uintptr(unsafe.Pointer(pName)),
		0,
		uintptr(unsafe.Pointer(&sidSize)),
		0,
		uintptr(unsafe.Pointer(&domSize)),
		uintptr(unsafe.Pointer(&sidUse)),
	)
	if sidSize == 0 {
		return nil, 0, fmt.Errorf("LookupAccountNameW: could not determine SID buffer size for %s", name)
	}
	sid := make([]byte, sidSize)
	dom := make([]uint16, domSize)
	ret, _, err := procLookupAccountName.Call(
		0,
		uintptr(unsafe.Pointer(pName)),
		uintptr(unsafe.Pointer(&sid[0])),
		uintptr(unsafe.Pointer(&sidSize)),
		uintptr(unsafe.Pointer(&dom[0])),
		uintptr(unsafe.Pointer(&domSize)),
		uintptr(unsafe.Pointer(&sidUse)),
	)
	if ret == 0 {
		return nil, 0, fmt.Errorf("LookupAccountNameW failed for %s: %v", name, err)
	}
	return sid, sidUse, nil
}

// ConvertSidToString converts a raw SID byte slice into the standard textual
// SID representation (e.g. S-1-5-32-544). Caller must handle errors.
func ConvertSidToString(sid []byte) (string, error) {
	if len(sid) == 0 {
		return "", fmt.Errorf("empty SID")
	}
	var pStr uintptr
	ret, _, err := procConvertSidToString.Call(
		uintptr(unsafe.Pointer(&sid[0])),
		uintptr(unsafe.Pointer(&pStr)),
	)
	if ret == 0 {
		return "", fmt.Errorf("ConvertSidToStringSidW failed: %v", err)
	}
	if pStr == 0 {
		return "", fmt.Errorf("ConvertSidToStringSidW returned NULL")
	}
	// pStr is LPWSTR (pointer to UTF-16). Convert to Go string.
	wptr := (*uint16)(unsafe.Pointer(pStr))
	s := windows.UTF16PtrToString(wptr)
	// Free memory allocated by ConvertSidToStringSidW
	if procLocalFree != nil {
		procLocalFree.Call(pStr)
	}
	return s, nil
}
