// Copyright 2026 OpenPubkey
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

package commands

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/openpubkey/opkssh/commands/config"
	"github.com/openpubkey/opkssh/policy/files"
	"github.com/spf13/afero"
)

// loadServerConfig reads and checks the server config file.
//
// The file is optional (files.RequiredPerms.Config.MustExist is false): a
// missing file yields an empty configuration. Otherwise the file must be
// owned by root with mode 0640, and its group must be one of allowedGroups.
// An empty allowedGroups skips the group check.
func loadServerConfig(afs afero.Fs, permChecker files.PermsChecker, path string, allowedGroups []string) (*config.ServerConfig, error) {
	configBytes, err := afero.ReadFile(afs, path)
	if errors.Is(err, fs.ErrNotExist) {
		return &config.ServerConfig{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	if err := permChecker.CheckPerm(path, []fs.FileMode{0o640}, "root", ""); err != nil {
		return nil, err
	}
	if err := checkConfigGroup(permChecker, path, allowedGroups); err != nil {
		return nil, err
	}

	serverConfig, err := config.NewServerConfig(configBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}
	return serverConfig, nil
}

// checkConfigGroup accepts the file if its group matches any allowed group.
// config.yml can hold env_vars such as proxy credentials, so it must not be
// readable by an arbitrary group such as "users".
func checkConfigGroup(permChecker files.PermsChecker, path string, allowedGroups []string) error {
	if len(allowedGroups) == 0 {
		return nil
	}
	var lastErr error
	for _, group := range allowedGroups {
		if lastErr = permChecker.CheckPerm(path, []fs.FileMode{0o640}, "", group); lastErr == nil {
			return nil
		}
	}
	return fmt.Errorf("config file group must be one of [%s]: %w", strings.Join(allowedGroups, ", "), lastErr)
}
