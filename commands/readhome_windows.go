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

//go:build windows

package commands

import (
	"bytes"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/openpubkey/opkssh/policy/files"
	"github.com/spf13/afero"
)

// ReadHome reads the home policy file for the user with the specified
// username on Windows. It verifies file ownership via the file's ACL
// owner SID to ensure the policy file belongs to the expected user.
func ReadHome(username string) ([]byte, error) {
	// Validate username: allow alphanumeric, dash, dot, underscore
	if matched, _ := regexp.MatchString(`^[a-zA-Z0-9_\-.]+$`, username); !matched {
		return nil, fmt.Errorf("%s is not a valid Windows username", username)
	}

	// Look up the user to get their SID and home directory
	userObj, err := user.Lookup(username)
	if err != nil {
		// On Windows, user.Lookup may need DOMAIN\user format. Try with
		// the bare username first, then fall back if needed.
		return nil, fmt.Errorf("failed to find user %s: %w", username, err)
	}

	homePolicyPath := filepath.Join(userObj.HomeDir, ".opk", "auth_id")

	// Verify file exists
	if _, err := os.Stat(homePolicyPath); err != nil {
		return nil, fmt.Errorf("failed to access %s: %w", homePolicyPath, err)
	}

	// Resolve the expected owner SID from the user object
	expectedSID, _, err := files.ResolveAccountToSID(username)
	if err != nil {
		// Try with the full username which may include domain prefix
		expectedSID, _, err = files.ResolveAccountToSID(userObj.Username)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve SID for user %s: %w", username, err)
		}
	}

	// Verify file ownership via ACL: check the file owner SID matches the user
	fs := afero.NewOsFs()
	verifier := files.NewDefaultACLVerifier(fs)
	report, err := verifier.VerifyACL(homePolicyPath, files.ExpectedACLFromPerm(files.RequiredPerms.HomePolicy))
	if err != nil {
		return nil, fmt.Errorf("failed to verify ACL on %s: %w", homePolicyPath, err)
	}

	// Compare owner SIDs
	if len(report.OwnerSID) == 0 {
		return nil, fmt.Errorf("could not determine file owner for %s", homePolicyPath)
	}
	if !bytes.Equal(report.OwnerSID, expectedSID) {
		// Convert SIDs to string form for a readable error message
		expectedSIDStr := userObj.Uid // user.User.Uid is the SID on Windows
		actualSIDStr := report.OwnerSIDStr
		if actualSIDStr == "" {
			actualSIDStr = "<unknown>"
		}
		ownerName := report.Owner
		if ownerName == "" {
			ownerName = actualSIDStr
		}
		return nil, fmt.Errorf("unsafe file ownership on %s: expected owner %s (SID %s) got %s (SID %s)",
			homePolicyPath, username, expectedSIDStr, ownerName, actualSIDStr)
	}

	// Verify there are no ACL problems flagged
	if len(report.Problems) > 0 {
		return nil, fmt.Errorf("ACL problems on %s: %s", homePolicyPath, strings.Join(report.Problems, "; "))
	}

	// Read and return file contents
	content, err := os.ReadFile(homePolicyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", homePolicyPath, err)
	}
	return content, nil
}
