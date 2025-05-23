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

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type KeyManagementConfig struct {
	DefaultKeyDir     string `yaml:"default_key_dir"`
	UseIdentityConfig bool   `yaml:"use_identity_config"`
}

func (k *KeyManagementConfig) GetKeyDir() (string, error) {

	var err error

	keyDir := ""
	configuredKeyDir := k.DefaultKeyDir

	// if the path is not absolute we will assume the users home directory
	if !filepath.IsAbs(configuredKeyDir) {
		keyDir, err = os.UserHomeDir()
		if err != nil {
			return "", err
		}

		// trim ~ prefix
		configuredKeyDir = strings.TrimPrefix(configuredKeyDir, "~/")
	}

	keyDir = filepath.Join(keyDir, configuredKeyDir)

	return filepath.Clean(keyDir), nil
}

// IsConfiguredToNameKeys
//
// Returns true if config requires key naming.
// Forced true if UseIdentityConfig is true.
func (k *KeyManagementConfig) IsConfiguredToNameKeys() bool {

	// can not be used if no path is set
	if k.DefaultKeyDir == "" {
		fmt.Println("KeyManagement disabled: no default key directory set")
		return false
	}

	// non-default path
	if k.DefaultKeyDir != "~/.ssh" {
		return true
	}

	// identity management via SSH config
	if k.UseIdentityConfig {
		return true
	}

	return false
}
