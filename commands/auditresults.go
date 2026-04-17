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
	"github.com/openpubkey/opkssh/internal/sysdetails"
	"github.com/openpubkey/opkssh/policy"
)

// ProviderResults records the results of auditing a provider file, e.g. /etc/opk/providers
type ProviderResults struct {
	FilePath string `json:"file_path"`
	// Error records any permission errors found on the provider file
	Error string `json:"error"`
}

// PolicyFileResult records the results of auditing a policy file, e.g. /etc/opk/auth_id or ~/.opk/auth_id
type PolicyFileResult struct {
	FilePath string `json:"file_path"`
	// The validation results for each row in the policy file
	Rows []policy.ValidationRowResult `json:"rows"`
	// Error records any errors found in reading the policy file
	Error string `json:"error"`
	// PermsError records any permission errors found on the policy file
	PermsError string `json:"perms_error"`
}

// TotalResults aggregates all results of the audit
type TotalResults struct {
	// Overall status of the audit, true if the audit did not find any problems
	Ok bool `json:"ok"`
	// Username of the process that ran the audit
	Username         string             `json:"username"`
	ProviderFile     ProviderResults    `json:"providers_file"`
	SystemPolicyFile PolicyFileResult   `json:"system_policy"`
	HomePolicyFiles  []PolicyFileResult `json:"home_policy"`
	OpkVersion       string             `json:"opk_version"`
	OpenSSHVersion   string             `json:"openssh_version"`
	OsInfo           string             `json:"os_info"`
}

func (t *TotalResults) SetOsInfo() {
	t.OsInfo = string(sysdetails.DetectOS())
}

func (t *TotalResults) SetOpenSSHVersion() {
	t.OpenSSHVersion = sysdetails.GetOpenSSHVersion()
}

func (t *TotalResults) SetOk() {
	t.Ok = t.EvaluateOk()
}

func (t *TotalResults) EvaluateOk() bool {
	if t.SystemPolicyFile.Error != "" || t.SystemPolicyFile.PermsError != "" {
		return false
	}
	for _, row := range t.SystemPolicyFile.Rows {
		if row.Status != policy.StatusSuccess {
			return false
		}
	}
	for _, homePolicy := range t.HomePolicyFiles {
		if homePolicy.Error != "" || homePolicy.PermsError != "" {
			return false
		}
		for _, row := range homePolicy.Rows {
			if row.Status != policy.StatusSuccess {
				return false
			}
		}
	}
	if t.ProviderFile.Error != "" {
		return false
	}

	// No errors encountered
	return true
}
