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

package main

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

const defaultSocketPath = "/run/opkssh/nss.sock"
const defaultAuthIDPath = "/etc/opk/auth_id"
const defaultHomedir = "/home"
const defaultShell = "/bin/bash"
const defaultUIDMin = 60000
const defaultUIDMax = 65534
const defaultGID = 60000

type Config struct {
	SocketPath string
	AuthIDPath string
	HomeDir    string
	Shell      string
	UIDMin     uint32
	UIDMax     uint32
	GID        uint32
}

func DefaultConfig() *Config {
	return &Config{
		SocketPath: defaultSocketPath,
		AuthIDPath: defaultAuthIDPath,
		HomeDir:    defaultHomedir,
		Shell:      defaultShell,
		UIDMin:     defaultUIDMin,
		UIDMax:     defaultUIDMax,
		GID:        defaultGID,
	}
}

// LoadConfig reads /etc/opk/nss.conf if present, layering over defaults.
// File format: key = value (one per line, # comments).
func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()

	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return cfg, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)

		switch k {
		case "socket_path":
			cfg.SocketPath = v
		case "auth_id":
			cfg.AuthIDPath = v
		case "home_dir":
			cfg.HomeDir = v
		case "shell":
			cfg.Shell = v
		case "uid_min":
			if n, err := strconv.ParseUint(v, 10, 32); err == nil {
				cfg.UIDMin = uint32(n)
			}
		case "uid_max":
			if n, err := strconv.ParseUint(v, 10, 32); err == nil {
				cfg.UIDMax = uint32(n)
			}
		case "gid":
			if n, err := strconv.ParseUint(v, 10, 32); err == nil {
				cfg.GID = uint32(n)
			}
		}
	}
	return cfg, scanner.Err()
}
