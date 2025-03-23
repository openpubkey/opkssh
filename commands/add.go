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
	"errors"
	"fmt"
	"os"

	"github.com/openpubkey/opkssh/policy"
)

// AddCmd provides functionality to read and update the opkssh policy file
type AddCmd struct {
	HomePolicyLoader   *policy.HomePolicyLoader
	SystemPolicyLoader *policy.SystemPolicyLoader

	// Username is the username to lookup when the system policy file cannot be
	// read and we fallback to the user's policy file.
	//
	// See AddCmd.LoadPolicy for more details.
	Username string
}

// LoadPolicy reads the opkssh policy at the policy.SystemDefaultPolicyPath. If
// there is a permission error when reading this file, then the user's local
// policy file (defined as ~/.opk/auth_id where ~ maps to AddCmd.Username's
// home directory) is read instead.
//
// If successful, returns the parsed policy and filepath used to read the
// policy. Otherwise, a non-nil error is returned.
func (a *AddCmd) LoadPolicy() (*policy.Policy, string, error) {
	// Try to read system policy first
	systemPolicy, _, err := a.SystemPolicyLoader.LoadSystemPolicy()
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			// If current process doesn't have permission, try reading the user
			// policy file.
			userPolicy, policyFilePath, err := a.HomePolicyLoader.LoadHomePolicy(a.Username, false)
			if err != nil {
				return nil, "", err
			}
			return userPolicy, policyFilePath, nil
		} else {
			// Non-permission error (e.g. system policy file missing or invalid
			// permission bits set). Return error
			return nil, "", err
		}
	}

	return systemPolicy, policy.SystemDefaultPolicyPath, nil
}

// GetPolicyPath returns the path to the policy file that the current command
// will write to and a boolean to flag the path is for home policy.
// True means home policy, false means system policy.
func (a *AddCmd) GetPolicyPath(principal string, userEmail string, issuer string) (string, bool, error) {
	// Try to read system policy first
	_, _, err := a.SystemPolicyLoader.LoadSystemPolicy()
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			// If current process doesn't have permission, try reading the user
			// policy file.
			policyFilePath, err := a.HomePolicyLoader.UserPolicyPath(a.Username)
			if err != nil {
				return "", false, err
			}
			return policyFilePath, false, nil
		} else {
			// Non-permission error (e.g. system policy file missing or invalid
			// permission bits set). Return error
			return "", false, err
		}
	}
	return policy.SystemDefaultPolicyPath, true, nil
}

// Add adds a new allowed principal to the user whose email is equal to
// userEmail. The policy file is read and modified.
//
// If successful, returns the policy filepath updated. Otherwise, returns a
// non-nil error
func (a *AddCmd) Add(principal string, userEmail string, issuer string) (string, error) {
	policyPath, useSystemPolicy, err := a.GetPolicyPath(principal, userEmail, issuer)
	if err != nil {
		return "", fmt.Errorf("failed to load policy: %w", err)
	}

	var policyLoader *policy.PolicyLoader
	if useSystemPolicy {
		policyLoader = a.SystemPolicyLoader.PolicyLoader
	} else {
		policyLoader = a.HomePolicyLoader.PolicyLoader
	}

	err = policyLoader.CreateIfDoesNotExist(policyPath)
	if err != nil {
		return "", fmt.Errorf("failed to create policy file: %w", err)
	}

	// Read current policy
	currentPolicy, policyFilePath, err := a.LoadPolicy()
	if err != nil {
		return "", fmt.Errorf("failed to load current policy: %w", err)
	}

	// Update policy
	currentPolicy.AddAllowedPrincipal(principal, userEmail, issuer)

	// Dump contents back to disk
	err = policyLoader.Dump(currentPolicy, policyFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to write updated policy: %w", err)
	}

	return policyFilePath, nil
}
