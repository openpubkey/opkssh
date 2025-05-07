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
	Name            string `yaml:"name"`
	CommandTemplate string `yaml:"command"`
}

// PercentExpand replaces  substrings in the command template that match the
// pattern %{token} if they exist in the supplied tokenMap. For instance
// if CommandTemplate was "/bin/echo %{email}" and the tokenMap contained
// {"iss": "alice@gmail.com"} this would be expanded to the string
// "/bin/echo alice@gmail.com". We then shellquote and split the command into
// a slice of strings, e.g. ["/bin/echo", "alice@gmail.com"].
//
// It is security critical to ensure that values in the tokenMap can not inject
// new commands or shell commands into the command template.
func (c PluginConfig) PercentExpand(tokenMap map[string]string) ([]string, error) {
	commandStr := ""
	tokenIndex := -1
	for i := 0; i < len(c.CommandTemplate); i++ {
		ch := c.CommandTemplate[i]
		if ch == '%' && i != len(c.CommandTemplate)-1 && c.CommandTemplate[i+1] == '%' {
			// We allow escaping % with %% and we have hit %%,
			commandStr += "%"
			i++ // Skip the next %
		} else if ch == '%' && i != len(c.CommandTemplate)-1 && c.CommandTemplate[i+1] == '{' {
			tokenIndex = i
			i++ // Skip past to the {
		} else if ch == '}' && tokenIndex != -1 {
			token := c.CommandTemplate[tokenIndex:(i + 1)]

			if value, ok := tokenMap[token]; ok {
				// Expand the token into the value in the tokenMap
				valueEscaped := shellquote.Join(value) // We shellquote the value to handle claims that have whitespace in them
				commandStr += valueEscaped
			} else {
				return nil, fmt.Errorf("invalid token %s", token)
			}

			tokenIndex = -1
		} else if tokenIndex == -1 {
			commandStr += string(ch)
		}
	}
	if tokenIndex != -1 {
		return nil, fmt.Errorf("unmatched { in at position (%d) in command template: %s", tokenIndex, c.CommandTemplate)
	}

	cmdParsed, err := shellquote.Split(commandStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse command field: %w", err)
	}
	return cmdParsed, nil
}
