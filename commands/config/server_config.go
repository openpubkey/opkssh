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
	"time"

	"github.com/openpubkey/openpubkey/discover"
	"github.com/openpubkey/opkssh/commands/discoverycache"
	"github.com/spf13/afero"
	"gopkg.in/yaml.v3"
)

// CacheConfig controls persistent caching of OIDC JWKS documents on a server.
// An empty BaseDir disables persistent caching.
type CacheConfig struct {
	BaseDir        string        `yaml:"base_dir"`
	StandardMaxAge time.Duration `yaml:"max_age"`
	FallbackMaxAge time.Duration `yaml:"fallback_max_age"`
}

// ServerConfig struct to represent the /etc/opk/config.yml file that runs on the server that the user is SSHing into
type ServerConfig struct {
	EnvVars    map[string]string `yaml:"env_vars"`
	DenyUsers  []string          `yaml:"deny_users"`
	DenyEmails []string          `yaml:"deny_emails"`
	Cache      CacheConfig       `yaml:"cache"`
}

func NewServerConfig(c []byte) (*ServerConfig, error) {
	var serverConfig ServerConfig
	if len(c) == 0 {
		c = []byte("{}")
	}
	if err := yaml.Unmarshal(c, &serverConfig); err != nil {
		return nil, err
	}

	return &serverConfig, nil
}

func (c *ServerConfig) SetEnvVars() error {
	for k, v := range c.EnvVars {
		if err := os.Setenv(k, v); err != nil {
			return err
		}
	}
	return nil
}

// DiscoveryCacheConfig returns the cache settings used by provider verifiers.
// Defaults are applied only when a persistent cache is configured.
func (c CacheConfig) DiscoveryCacheConfig(fs afero.Fs) (discover.DiscoveryCacheConfig, error) {
	if c.BaseDir == "" {
		return discover.DiscoveryCacheConfig{}, nil
	}
	if fs == nil {
		return discover.DiscoveryCacheConfig{}, fmt.Errorf("cache filesystem is required")
	}

	standardMaxAge := c.StandardMaxAge
	if standardMaxAge == 0 {
		standardMaxAge = time.Hour
	}
	if standardMaxAge < 0 {
		return discover.DiscoveryCacheConfig{}, fmt.Errorf("cache max_age must not be negative")
	}
	fallbackMaxAge := c.FallbackMaxAge
	if fallbackMaxAge == 0 {
		fallbackMaxAge = 2 * standardMaxAge
	}
	if fallbackMaxAge < 0 {
		return discover.DiscoveryCacheConfig{}, fmt.Errorf("cache fallback_max_age must not be negative")
	}
	if fallbackMaxAge < standardMaxAge {
		return discover.DiscoveryCacheConfig{}, fmt.Errorf("cache fallback_max_age (%s) must not be less than max_age (%s)", fallbackMaxAge, standardMaxAge)
	}

	cache := discoverycache.NewFilesystemDiscoveryCache(fs, c.BaseDir)
	if err := cache.Validate(); err != nil {
		return discover.DiscoveryCacheConfig{}, err
	}

	return discover.DiscoveryCacheConfig{
		Cache:          cache,
		StandardMaxAge: standardMaxAge,
		FallbackMaxAge: fallbackMaxAge,
	}, nil
}
