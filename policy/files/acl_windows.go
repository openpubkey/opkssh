//go:build windows
// +build windows

package files

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"github.com/spf13/afero"
)

// maskToRights maps common Windows access mask bits to readable names.
func maskToRights(mask uint32) string {
	var parts []string
	if mask&0x80000000 != 0 {
		parts = append(parts, "GENERIC_READ")
	}
	if mask&0x40000000 != 0 {
		parts = append(parts, "GENERIC_WRITE")
	}
	if mask&0x20000000 != 0 {
		parts = append(parts, "GENERIC_EXECUTE")
	}
	if mask&0x10000000 != 0 {
		parts = append(parts, "GENERIC_ALL")
	}
	// File-specific
	if mask&0x00000001 != 0 {
		parts = append(parts, "FILE_READ_DATA")
	}
	if mask&0x00000002 != 0 {
		parts = append(parts, "FILE_WRITE_DATA")
	}
	if mask&0x00000004 != 0 {
		parts = append(parts, "FILE_APPEND_DATA")
	}
	if mask&0x00000008 != 0 {
		parts = append(parts, "FILE_READ_EA")
	}
	if mask&0x00000010 != 0 {
		parts = append(parts, "FILE_WRITE_EA")
	}
	if mask&0x00000020 != 0 {
		parts = append(parts, "FILE_EXECUTE")
	}
	if mask&0x00000040 != 0 {
		parts = append(parts, "FILE_DELETE_CHILD")
	}
	if mask&0x00000080 != 0 {
		parts = append(parts, "FILE_READ_ATTRIBUTES")
	}
	if mask&0x00000100 != 0 {
		parts = append(parts, "FILE_WRITE_ATTRIBUTES")
	}
	// Standard rights
	if mask&0x00010000 != 0 {
		parts = append(parts, "DELETE")
	}
	if mask&0x00020000 != 0 {
		parts = append(parts, "READ_CONTROL")
	}
	if mask&0x00040000 != 0 {
		parts = append(parts, "WRITE_DAC")
	}
	if mask&0x00080000 != 0 {
		parts = append(parts, "WRITE_OWNER")
	}
	if mask&0x00100000 != 0 {
		parts = append(parts, "SYNCHRONIZE")
	}
	if len(parts) == 0 {
		return fmt.Sprintf("0x%x", mask)
	}
	return strings.Join(parts, ",")
}

var (
	advapi32              = syscall.NewLazyDLL("advapi32.dll")
	procGetNamedSecInfo   = advapi32.NewProc("GetNamedSecurityInfoW")
	procLookupAccountSid  = advapi32.NewProc("LookupAccountSidW")
	procGetLengthSid      = advapi32.NewProc("GetLengthSid")
	procGetAclInformation = advapi32.NewProc("GetAclInformation")
	procGetAce            = advapi32.NewProc("GetAce")
	kernel32              = syscall.NewLazyDLL("kernel32.dll")
	procLocalFree         = kernel32.NewProc("LocalFree")
)

const (
	SE_FILE_OBJECT             = 1
	OWNER_SECURITY_INFORMATION = 0x00000001
	DACL_SECURITY_INFORMATION  = 0x00000004
	AclSizeInformation         = 2
	INHERITED_ACE              = 0x10
	ACCESS_ALLOWED_ACE_TYPE    = 0
	ACCESS_DENIED_ACE_TYPE     = 1
)

// WindowsACLVerifier implements ACLVerifier on Windows using Win32 APIs.
// It obtains the file owner and enumerates ACEs from the DACL.
type WindowsACLVerifier struct {
	Fs afero.Fs
}

func NewDefaultACLVerifier(fs afero.Fs) ACLVerifier {
	return &WindowsACLVerifier{Fs: fs}
}

func utf16PtrFromStringNullable(s string) (*uint16, error) {
	if s == "" {
		return nil, nil
	}
	return syscall.UTF16PtrFromString(s)
}

func (w *WindowsACLVerifier) VerifyACL(path string, expected ExpectedACL) (ACLReport, error) {
	r := ACLReport{Path: path}
	if w.Fs == nil {
		w.Fs = afero.NewOsFs()
	}
	if _, err := w.Fs.Stat(path); err != nil {
		r.Exists = false
		r.Problems = append(r.Problems, fmt.Sprintf("open %s: %v", path, err))
		return r, nil
	}
	r.Exists = true

	// Call GetNamedSecurityInfoW to get owner SID, DACL and security descriptor
	pPath, _ := utf16PtrFromStringNullable(path)
	var pOwner uintptr
	var pDacl uintptr
	var pSD uintptr
	// Get owner and DACL
	flags := OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
	ret, _, _ := procGetNamedSecInfo.Call(
		uintptr(unsafe.Pointer(pPath)),
		uintptr(SE_FILE_OBJECT),
		uintptr(flags),
		uintptr(unsafe.Pointer(&pOwner)),
		0,
		uintptr(unsafe.Pointer(&pDacl)),
		0,
		uintptr(unsafe.Pointer(&pSD)),
	)
	if ret != 0 {
		r.Problems = append(r.Problems, fmt.Sprintf("GetNamedSecurityInfoW failed: error=%d", ret))
		return r, nil
	}
	// Ensure security descriptor memory is freed
	if pSD != 0 {
		defer procLocalFree.Call(pSD)
	}

	// Lookup owner name if available
	if pOwner != 0 {
		// Copy owner SID raw bytes into report for precise assertions
		ownerSidLenRet, _, _ := procGetLengthSid.Call(pOwner)
		if ownerSidLenRet != 0 {
			ownerSidLen := int(ownerSidLenRet)
			ownerSidBytes := make([]byte, ownerSidLen)
			for i := 0; i < ownerSidLen; i++ {
				ownerSidBytes[i] = *(*byte)(unsafe.Pointer(pOwner + uintptr(i)))
			}
			r.OwnerSID = ownerSidBytes
			if s, err := ConvertSidToString(ownerSidBytes); err == nil {
				r.OwnerSIDStr = s
			}
		}

		var nameLen uint32
		var domLen uint32
		var sidUse uint32
		// First call to get sizes
		procLookupAccountSid.Call(
			0,
			pOwner,
			0,
			uintptr(unsafe.Pointer(&nameLen)),
			0,
			uintptr(unsafe.Pointer(&domLen)),
			uintptr(unsafe.Pointer(&sidUse)),
		)
		if nameLen != 0 {
			name := make([]uint16, nameLen)
			dom := make([]uint16, domLen)
			success, _, err := procLookupAccountSid.Call(
				0,
				pOwner,
				uintptr(unsafe.Pointer(&name[0])),
				uintptr(unsafe.Pointer(&nameLen)),
				uintptr(unsafe.Pointer(&dom[0])),
				uintptr(unsafe.Pointer(&domLen)),
				uintptr(unsafe.Pointer(&sidUse)),
			)
			if success == 0 {
				r.Problems = append(r.Problems, fmt.Sprintf("LookupAccountSidW failed: %v", err))
			} else {
				r.Owner = syscall.UTF16ToString(name)
				if expected.Owner != "" && r.Owner != expected.Owner {
					r.Problems = append(r.Problems, fmt.Sprintf("expected owner (%s), got (%s)", expected.Owner, r.Owner))
				}
			}
		} else {
			r.Problems = append(r.Problems, "LookupAccountSidW: could not determine required name buffer size")
		}
	} else {
		r.Problems = append(r.Problems, "owner SID not available")
	}

	// If DACL available, enumerate ACEs
	if pDacl != 0 {
		var info struct {
			AceCount      uint32
			AclBytesInUse uint32
			AclBytesFree  uint32
		}
		// GetAclInformation to retrieve AceCount
		ret2, _, _ := procGetAclInformation.Call(
			pDacl,
			uintptr(unsafe.Pointer(&info)),
			uintptr(unsafe.Sizeof(info)),
			uintptr(AclSizeInformation),
		)
		if ret2 == 0 {
			r.Problems = append(r.Problems, fmt.Sprintf("GetAclInformation failed: %d", ret2))
		} else {
			// iterate over ACEs
			for i := uint32(0); i < info.AceCount; i++ {
				var pAce uintptr
				r3, _, _ := procGetAce.Call(pDacl, uintptr(i), uintptr(unsafe.Pointer(&pAce)))
				if r3 == 0 || pAce == 0 {
					r.Problems = append(r.Problems, fmt.Sprintf("GetAce failed for index %d", i))
					continue
				}
				// Read ACE header: Type(1), Flags(1), Size(2)
				aceType := *(*byte)(unsafe.Pointer(pAce))
				aceFlags := *(*byte)(unsafe.Pointer(pAce + 1))
				// Mask is at offset 4 (after 4-byte header)
				mask := *(*uint32)(unsafe.Pointer(pAce + 4))
				sidPtr := pAce + 8

				// Lookup account name for SID
				var nameLen uint32
				var domLen uint32
				var sidUse uint32
				procLookupAccountSid.Call(
					0,
					sidPtr,
					0,
					uintptr(unsafe.Pointer(&nameLen)),
					0,
					uintptr(unsafe.Pointer(&domLen)),
					uintptr(unsafe.Pointer(&sidUse)),
				)
				principal := "<unknown>"
				if nameLen != 0 {
					name := make([]uint16, nameLen)
					dom := make([]uint16, domLen)
					success, _, err := procLookupAccountSid.Call(
						0,
						sidPtr,
						uintptr(unsafe.Pointer(&name[0])),
						uintptr(unsafe.Pointer(&nameLen)),
						uintptr(unsafe.Pointer(&dom[0])),
						uintptr(unsafe.Pointer(&domLen)),
						uintptr(unsafe.Pointer(&sidUse)),
					)
					if success != 0 {
						principal = syscall.UTF16ToString(name)
					} else {
						_ = err
					}
				}

				// Copy SID bytes so callers/tests can assert exact SIDs
				var sidBytes []byte
				// GetLengthSid returns the size of the SID in bytes
				sidLenRet, _, _ := procGetLengthSid.Call(sidPtr)
				if sidLenRet != 0 {
					sidLen := int(sidLenRet)
					sidBytes = make([]byte, sidLen)
					for idx := 0; idx < sidLen; idx++ {
						b := *(*byte)(unsafe.Pointer(sidPtr + uintptr(idx)))
						sidBytes[idx] = b
					}
				}

				rights := maskToRights(mask)
				ace := ACE{
					Principal:       principal,
					PrincipalSID:    sidBytes,
					PrincipalSIDStr: "",
					Rights:          rights,
					Type: func() string {
						if aceType == ACCESS_ALLOWED_ACE_TYPE {
							return "allow"
						}
						if aceType == ACCESS_DENIED_ACE_TYPE {
							return "deny"
						}
						return fmt.Sprintf("type-%d", aceType)
					}(),
					Inherited: (aceFlags & INHERITED_ACE) != 0,
				}

				// Convert SID bytes to textual SID for easier assertions/logging
				if len(sidBytes) > 0 {
					if s, err := ConvertSidToString(sidBytes); err == nil {
						ace.PrincipalSIDStr = s
					}
				}
				r.ACEs = append(r.ACEs, ace)
			}
		}
	}

	return r, nil
}
