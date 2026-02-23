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

package files

// RequiredPerms defines the expected permissions for each opkssh resource type
// on Windows systems.
var RequiredPerms = struct {
	// SystemPolicy is the system-wide policy file
	// (e.g. %ProgramData%\opk\auth_id).
	SystemPolicy PermInfo
	// HomePolicy is the per-user policy file
	// (e.g. ~/.opk/auth_id).
	HomePolicy PermInfo
	// ProvidersDir is the directory containing provider configuration
	// (e.g. %ProgramData%\opk\providers).
	ProvidersDir PermInfo
	// PluginsDir is the directory containing policy plugin definitions
	// (e.g. %ProgramData%\opk\policy.d).
	PluginsDir PermInfo
	// PluginFile is an individual plugin YAML file inside the plugins
	// directory.
	PluginFile PermInfo
}{
	SystemPolicy: PermInfo{
		Mode:      ModeSystemPerms, // 0640
		Owner:     "Administrators",
		Group:     "",
		MustExist: true,
	},
	HomePolicy: PermInfo{
		Mode:      ModeHomePerms, // 0600
		Owner:     "",            // owner is the user themselves
		Group:     "",
		MustExist: false,
	},
	ProvidersDir: PermInfo{
		Mode:      0750,
		Owner:     "Administrators",
		Group:     "",
		MustExist: false,
	},
	PluginsDir: PermInfo{
		Mode:      0750,
		Owner:     "Administrators",
		Group:     "",
		MustExist: false,
	},
	PluginFile: PermInfo{
		Mode:      ModeSystemPerms, // 0640
		Owner:     "Administrators",
		Group:     "",
		MustExist: false,
	},
}
