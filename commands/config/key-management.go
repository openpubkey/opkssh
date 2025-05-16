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
	"os"
	"path/filepath"
	"strings"
)

type KeyManagementConfig struct {
	DefaultKeyDir     string `yaml:"default_key_dir"`
	UseIdentityConfig bool   `yaml:"use_identity_config"`
}

func (k *KeyManagementConfig) GetKeyDir() (configKeyDir string, err error) {

	if !strings.HasPrefix(k.DefaultKeyDir, "/") {
		configKeyDir, err = os.UserHomeDir()
		if err != nil {
			return
		}
	}

	configKeyDir = filepath.Join(configKeyDir, k.DefaultKeyDir)

	return
}
