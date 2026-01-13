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

import "github.com/openpubkey/opkssh/policy"

// TotalResults aggregates all results of the audit
type TotalResults struct {
	// Overall status of the audit, true if the audit did not find any problems
	Ok bool
	// Username of the process that ran the audit
	Username         string
	ProviderResults  ProviderResults
	SystemPolicyFile PolicyFileResult
	HomePolicyFiles  []PolicyFileResult
}

// ProviderResults records the results of auditing a provider file, e.g. /etc/opk/providers
type ProviderResults struct {
	FilePath string
	// Error records any permission errors found on the provider file
	Error string
}

// PolicyFileResult records the results of auditing a policy file, e.g. /etc/opk/auth_id or ~/.opk/auth_id
type PolicyFileResult struct {
	FilePath string
	// The validation results for each row in the policy file
	Row []policy.ValidationRowResult
	// Error records any errors found in reading the policy file
	Error string
	// PermsError records any permission errors found on the policy file
	PermsError string
}
