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
	"log"
	"os/exec"
	"strings"
)

// getOpenSSHVersion attempts to get OpenSSH version using multiple fallback methods
func GetOpenSSHVersion() string {
	// OS-specific package manager queries
	osType := DetectOS()
	log.Printf("Attempting OS-specific version detection for: %s", osType)

	switch osType {
	case OSTypeRHEL:
		// For RedHat-based systems (CentOS, RHEL, Fedora)
		cmd := exec.Command("/bin/sh", "-c", "version=$(/usr/bin/rpm -q --qf \"%{VERSION}\\n\" openssh-server 2>/dev/null | /bin/sed -E 's/^([0-9]+\\.[0-9]+).*/\\1/' | head -1); if [ -n \"$version\" ]; then /bin/echo \"OpenSSH_$version\"; fi")
		if output, err := cmd.CombinedOutput(); err == nil && len(strings.TrimSpace(string(output))) > 0 {
			return strings.TrimSpace(string(output))
		}

	case OSTypeDebian:
		// For Debian-based systems (Debian, Ubuntu)
		cmd := exec.Command("/bin/sh", "-c", "version=$(/usr/bin/dpkg-query -W -f='${Version}\\n' openssh-server 2>/dev/null | /bin/sed -E 's/^[0-9]*:?([0-9]+\\.[0-9]+).*/\\1/' | head -1); if [ -n \"$version\" ]; then /bin/echo \"OpenSSH_$version\"; fi")
		if output, err := cmd.CombinedOutput(); err == nil && len(strings.TrimSpace(string(output))) > 0 {
			return strings.TrimSpace(string(output))
		}

	case OSTypeArch:
		// For Arch Linux
		cmd := exec.Command("/bin/sh", "-c", "version=$(/usr/bin/pacman -Qi openssh 2>/dev/null | /usr/bin/awk '/^Version/ {print $3}' | /bin/sed -E 's/^([0-9]+\\.[0-9]+).*/\\1/' | head -1); if [ -n \"$version\" ]; then /bin/echo \"OpenSSH_$version\"; fi")
		if output, err := cmd.CombinedOutput(); err == nil && len(strings.TrimSpace(string(output))) > 0 {
			return strings.TrimSpace(string(output))
		}

	case OSTypeSUSE:
		// For SUSE-based systems
		cmd := exec.Command("/bin/sh", "-c", "version=$(/usr/bin/rpm -q --qf \"%{VERSION}\\n\" openssh 2>/dev/null | /bin/sed -E 's/^([0-9]+\\.[0-9]+).*/\\1/' | head -1); if [ -n \"$version\" ]; then /bin/echo \"OpenSSH_$version\"; fi")
		if output, err := cmd.CombinedOutput(); err == nil && len(strings.TrimSpace(string(output))) > 0 {
			return strings.TrimSpace(string(output))
		}

	case OSTypeWindows:
		// For Windows, try ssh.exe in PATH
		cmd := exec.Command("ssh.exe", "-V")
		output, err := cmd.CombinedOutput()
		if err == nil && len(strings.TrimSpace(string(output))) > 0 {
			return strings.TrimSpace(string(output))
		}

	default:
		log.Printf("Warning: Could not determine OpenSSH version using OS-specific methods for %s", osType)
	}

	// Try ssh -V (works on most systems)
	sshCmd := "ssh"
	if osType == OSTypeWindows {
		sshCmd = "ssh.exe"
	}
	cmd := exec.Command(sshCmd, "-V")
	output, err := cmd.CombinedOutput()
	if err == nil && len(strings.TrimSpace(string(output))) > 0 {
		return strings.TrimSpace(string(output))
	}
	log.Println("Warning: Error executing ssh -V:", err)

	// Try sshd -V as fallback
	sshdCmd := "sshd"
	if osType == OSTypeWindows {
		sshdCmd = "sshd.exe"
	}
	cmd = exec.Command(sshdCmd, "-V")
	output, err = cmd.CombinedOutput()
	if err == nil && len(strings.TrimSpace(string(output))) > 0 {
		return strings.TrimSpace(string(output))
	}
	log.Println("Warning: Error executing sshd -V:", err)

	return ""
}
