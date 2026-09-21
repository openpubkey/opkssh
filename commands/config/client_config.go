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
	AgentLifetime   string           `yaml:"agent_lifetime,omitempty"`
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

// ConfigPathFlagHelp documents the --config-path default resolution chain;
// shared by every command that carries the flag so the copies cannot drift.
const ConfigPathFlagHelp = "Path to the client config file. Default: the first existing of $XDG_CONFIG_HOME/opk/config.yml (~/.config/opk/config.yml on linux/macOS, %AppData%\\opk\\config.yml on windows) and the legacy ~/.opk/config.yml."

// clientConfigCandidatePaths returns the client config locations in
// resolution order:
//
//  1. <configDir>/opk/config.yml, where <configDir> is $XDG_CONFIG_HOME when
//     set and absolute (the XDG Base Directory spec requires relative values
//     to be ignored), otherwise the platform default (~/.config on Unix-like
//     systems, %AppData% on Windows). Replacement semantics per the spec: a
//     set variable replaces the platform default, it does not stack with it.
//  2. The legacy ~/.opk/config.yml.
func clientConfigCandidatePaths() ([]string, error) {
	var configDir string
	var platformDirErr error
	if xdgDir := os.Getenv("XDG_CONFIG_HOME"); xdgDir != "" && filepath.IsAbs(xdgDir) {
		configDir = xdgDir
	} else if platformDir, err := userConfigDir(); err == nil {
		configDir = platformDir
	} else {
		platformDirErr = err
	}

	var candidates []string
	if configDir != "" {
		candidates = append(candidates, filepath.Join(configDir, "opk", "config.yml"))
	}
	if homeDir, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(homeDir, ".opk", "config.yml"))
	} else {
		// Never drop the legacy candidate silently: a user whose only config
		// is the legacy one would get an unexplained fresh-config resolution.
		log.Printf("warning: could not determine home directory, ignoring legacy ~/.opk/config.yml: %v", err)
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("failed to determine the user config directory: %w", platformDirErr)
	}
	return candidates, nil
}

// ResolveClientConfigPath resolves the client config path and reports
// whether a config file exists there. An explicitly provided path is used
// as-is. Otherwise the first existing candidate wins (so a legacy
// ~/.opk/config.yml keeps working untouched), and when no config exists
// anywhere the path falls to the first candidate, the XDG-preferred
// location, which is where a new config is then created.
func ResolveClientConfigPath(fs afero.Fs, configPath *string) (bool, error) {
	afs := &afero.Afero{Fs: fs}
	if *configPath != "" {
		found, err := afs.Exists(*configPath)
		return err == nil && found, nil
	}
	candidates, err := clientConfigCandidatePaths()
	if err != nil {
		return false, err
	}
	for _, candidate := range candidates {
		if exists, err := afs.Exists(candidate); err == nil && exists {
			*configPath = candidate
			return true, nil
		}
	}
	*configPath = candidates[0]
	return false, nil
}

// GetClientConfigFromFile retrieves the client config from the configuration file at configPath.
// If configPath is not specified it is resolved via ResolveClientConfigPath
// (see clientConfigCandidatePaths for the resolution order).
func GetClientConfigFromFile(configPath string, Fs afero.Fs) (*ClientConfig, error) {
	if _, err := ResolveClientConfigPath(Fs, &configPath); err != nil {
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
	// 0700/0600: the client config can carry provider client_secret values.
	if err := afs.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}
	if err := afs.WriteFile(configPath, DefaultClientConfig, 0o600); err != nil {
		return fmt.Errorf("failed to write default config file: %w", err)
	}
	log.Printf("created client config file at %s", configPath)
	return nil
}
