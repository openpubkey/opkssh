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

type TotalResults struct {
	ProviderResults  ProviderResults
	SystemPolicyFile PolicyFileResult
	HomePolicyFiles  []PolicyFileResult
}

type ProviderResults struct {
	FilePath string
	// PermissionsError records any permission errors found on the provider file
	PermissionsError error
}

type PolicyFileResult struct {
	FilePath string
	// The validation results for each row in the policy file
	Row []policy.ValidationRowResult
	// PermissionsError records any permission errors found on the provider file
	PermissionsError error
}
