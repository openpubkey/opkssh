// Copyright 2026 OpenPubkey
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package sysdetails

import (
	"os"
	"runtime"
	"strings"
)

// OSType represents the operating system type
type OSType string

// Operating system constants
const (
	OSTypeGeneric OSType = "generic"
	OSTypeRHEL    OSType = "rhel"
	OSTypeDebian  OSType = "debian"
	OSTypeArch    OSType = "arch"
	OSTypeSUSE    OSType = "suse"
	OSTypeWindows OSType = "windows"
)

// DetectOS determines the type of operating system.
func DetectOS() OSType {
	// Check for Windows using runtime.GOOS
	if runtime.GOOS == "windows" {
		return OSTypeWindows
	}

	// Check for RedHat-based systems
	if _, err := os.Stat("/etc/redhat-release"); err == nil {
		return OSTypeRHEL
	}

	// Check for Debian-based systems
	if _, err := os.Stat("/etc/debian_version"); err == nil {
		return OSTypeDebian
	}

	// Check for Arch Linux
	if _, err := os.Stat("/etc/arch-release"); err == nil {
		return OSTypeArch
	}

	// Check for SUSE Linux
	if _, err := os.Stat("/etc/SuSE-release"); err == nil {
		return OSTypeSUSE
	}
	if _, err := os.Stat("/etc/SUSE-brand"); err == nil {
		return OSTypeSUSE
	}

	// Check for /etc/os-release which exists on most modern Linux systems
	if content, err := os.ReadFile("/etc/os-release"); err == nil {
		contentStr := string(content)
		if strings.Contains(contentStr, "ID=rhel") ||
			strings.Contains(contentStr, "ID=centos") ||
			strings.Contains(contentStr, "ID=fedora") {
			return OSTypeRHEL
		}
		if strings.Contains(contentStr, "ID=debian") ||
			strings.Contains(contentStr, "ID=ubuntu") {
			return OSTypeDebian
		}
		if strings.Contains(contentStr, "ID=arch") {
			return OSTypeArch
		}
		if strings.Contains(contentStr, "ID=sles") ||
			strings.Contains(contentStr, "ID=opensuse") {
			return OSTypeSUSE
		}
	}

	// Default to generic, if no specific OS type is detected.
	return OSTypeGeneric
}
