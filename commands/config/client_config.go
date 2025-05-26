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
	_ "embed"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed default-client-config.yml
var DefaultClientConfig []byte

type ClientConfig struct {
	DefaultProvider string              `yaml:"default_provider"`
	KeyManagement   KeyManagementConfig `yaml:"key_management"`
	Providers       []ProviderConfig    `yaml:"providers"`
}

func NewClientConfig(c []byte) (*ClientConfig, error) {
	var clientConfig ClientConfig
	if err := yaml.Unmarshal(c, &clientConfig); err != nil {
		return nil, err
	}

	return &clientConfig, nil
}

func (c *ClientConfig) GetProvidersMap() (map[string]ProviderConfig, error) {
	return CreateProvidersMap(c.Providers)
}

func (c *ClientConfig) CheckKeyDir() error {

	km := c.KeyManagement

	// do a simple sanity check on key dirs
	if strings.Contains(km.DefaultKeyDir, ".ssh/config") || strings.Contains(km.DefaultKeyDir, ".opk/config") {
		fmt.Println("WARNING: You might be using a config file name as a directory path. Make sure your path does not use .ssh/config or .opk/config")
	}

	// if default key dir is not set we use the default logic
	if km.DefaultKeyDir == "" ||
		// if identity management is off and default value is used we do the same
		(!km.UseIdentityConfig && km.DefaultKeyDir == "~/.ssh") {
		return nil
	}

	// if identity management is off and default value is not used we inform the user that the SSH client will not
	// use the key automatically
	if !km.UseIdentityConfig && km.DefaultKeyDir != "~/.ssh" {
		fmt.Println("Not using default key name and directory. SSH client will not automatically find the key pair!")
	}

	keyDir, err := km.GetKeyDir()
	if err != nil {
		return err
	}

	err = os.MkdirAll(keyDir, 0700)
	if err != nil {
		err = fmt.Errorf("failed to create key directory: %w", err)
		return err
	}

	fileInfo, err := os.Stat(keyDir)
	if err != nil {
		err = fmt.Errorf("could not get stats of key directory: %w", err)
		return err
	}

	if !fileInfo.IsDir() {
		err = fmt.Errorf("key directory is not a directory")
		return err
	}

	return nil
}
