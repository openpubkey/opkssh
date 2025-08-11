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

	"gopkg.in/yaml.v3"
)

// ServerConfig struct to represent the /etc/opk/config.yml file that runs on the server that the user is SSHing into
type ServerConfig struct {
	EnvVars    map[string]string `yaml:"env_vars"`
	DenyEmails []string          `yaml:"deny_emails"`
}

func NewServerConfig(c []byte) (*ServerConfig, error) {
	var serverConfig ServerConfig
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
