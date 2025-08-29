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
	"log"
	"os"
	"path/filepath"

	"github.com/spf13/afero"
	"gopkg.in/yaml.v3"
)

//go:embed default-client-config.yml
var DefaultClientConfig []byte

type ClientConfig struct {
	DefaultProvider string           `yaml:"default_provider"`
	Providers       []ProviderConfig `yaml:"providers"`
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

// GetByIssuer looks up an OpenID Provider by its issuer URL. If there are
// multiple providers with the same issuer, it returns the first one found.
func (c *ClientConfig) GetByIssuer(issuer string) (*ProviderConfig, bool) {
	for _, provider := range c.Providers {
		if provider.Issuer == issuer {
			return &provider, true
		}
	}
	return nil, false
}

func ResolveClientConfigPath(configPath *string) error {
	if *configPath == "" {
		dir, dirErr := os.UserHomeDir()
		if dirErr != nil {
			return fmt.Errorf("failed to get user config dir: %w", dirErr)
		}
		*configPath = filepath.Join(dir, ".opk", "config.yml")
	}
	return nil
}

// GetClientConfigFromFile retrieves the client config from the configuration file at configPath.
// If configPath is not specified then the default configuration path is uses ~/.opk/config.yml
func GetClientConfigFromFile(configPath string, Fs afero.Fs) (*ClientConfig, error) {
	if err := ResolveClientConfigPath(&configPath); err != nil {
		return nil, err
	}

	var configBytes []byte
	// Load the file from the filesystem
	afs := &afero.Afero{Fs: Fs}
	configBytes, err := afs.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}
	config, err := NewClientConfig(configBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}
	return config, nil
}

func CreateDefaultClientConfig(configPath string, Fs afero.Fs) error {
	afs := &afero.Afero{Fs: Fs}
	if err := afs.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}
	if err := afs.WriteFile(configPath, DefaultClientConfig, 0o644); err != nil {
		return fmt.Errorf("failed to write default config file: %w", err)
	}
	log.Printf("created client config file at %s", configPath)
	return nil
}
