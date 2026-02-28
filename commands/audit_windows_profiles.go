//go:build windows
// +build windows

// Copyright 2025 OpenPubkey
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

package commands

import (
	"fmt"
	"os/user"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// profileListKey is the registry path under HKLM where Windows stores a
// mapping of every SID that has ever logged in to its profile directory.
const profileListKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`

// getHomeDirsFromProfileList enumerates Windows user profiles from the
// registry ProfileList. This is the Windows equivalent of
// getHomeDirsFromEtcPasswd and returns one entry per real user (SID prefix
// S-1-5-21-) that has a profile directory on this machine.
func getHomeDirsFromProfileList() ([]etcPasswdRow, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, profileListKey,
		registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, fmt.Errorf("failed to open ProfileList registry key: %w", err)
	}
	defer key.Close()

	sids, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate ProfileList subkeys: %w", err)
	}

	var entries []etcPasswdRow
	for _, sid := range sids {
		// Real user SIDs start with S-1-5-21-; skip well-known SIDs like
		// SYSTEM (S-1-5-18), LOCAL SERVICE (S-1-5-19), NETWORK SERVICE
		// (S-1-5-20), etc.
		if !strings.HasPrefix(sid, "S-1-5-21-") {
			continue
		}

		subkey, err := registry.OpenKey(registry.LOCAL_MACHINE,
			profileListKey+`\`+sid, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		// GetStringValue already expands REG_EXPAND_SZ values.
		profilePath, _, err := subkey.GetStringValue("ProfileImagePath")
		subkey.Close()
		if err != nil || profilePath == "" {
			continue
		}

		// Resolve SID to username; skip if account has been deleted.
		u, err := user.LookupId(sid)
		if err != nil {
			continue
		}

		username := u.Username
		// Strip DOMAIN\ prefix if present (e.g. "COMPUTERNAME\alice" → "alice")
		if parts := strings.SplitN(username, `\`, 2); len(parts) == 2 {
			username = parts[1]
		}

		entries = append(entries, etcPasswdRow{
			Username: username,
			HomeDir:  profilePath,
		})
	}
	return entries, nil
}
