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

package plugins

import (
	"fmt"

	"github.com/kballard/go-shellquote"
)

// PluginConfig represents the structure of a policy command configuration.
type PluginConfig struct {
	Name             string `yaml:"name"`
	CommandTemplate  string `yaml:"command"`
	EnforceProviders bool   `yaml:"enforce_providers"`
}

func (c PluginConfig) PercentExpand(tokenMap map[string]string) ([]string, error) {
	commandStr := ""
	openPercentIndex := -1
	for i := 0; i < len(c.CommandTemplate); i++ {
		ch := c.CommandTemplate[i]
		if ch == '%' && i != len(c.CommandTemplate)-1 && c.CommandTemplate[i+1] == '%' {
			// We allow escaping % with %% and we have hit %%,
			commandStr += "%"
			i++ // Skip the next %
		} else if ch == '%' && openPercentIndex == -1 {
			openPercentIndex = i
		} else if ch == '%' && openPercentIndex != -1 {
			token := c.CommandTemplate[openPercentIndex:(i + 1)]

			if value, ok := tokenMap[token]; ok {
				// Expand the token into the value in the tokenMap
				valueEscaped := shellquote.Join(value) // We shellquote the value to handle claims that have whitespace in them
				commandStr += valueEscaped
			} else {
				return nil, fmt.Errorf("invalid token %s", token)
			}

			openPercentIndex = -1
		} else if openPercentIndex == -1 {
			commandStr += string(ch)
		}
	}
	if openPercentIndex != -1 {
		return nil, fmt.Errorf("unmatched %% in at position (%d) in command template: %s", openPercentIndex, c.CommandTemplate)
	}

	cmdParsed, err := shellquote.Split(commandStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse command field: %w", err)
	}
	return cmdParsed, nil
}
