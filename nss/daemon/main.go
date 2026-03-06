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
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

const configPath = "/etc/opk/nss.conf"

func main() {
	cfg, err := LoadConfig(configPath)
	if err != nil {
		log.Fatalf("loading config: %v", err)
	}

	// Ensure the socket directory exists.
	if err := os.MkdirAll(filepath.Dir(cfg.SocketPath), 0750); err != nil {
		log.Fatalf("creating socket directory: %v", err)
	}

	db := NewUserDB()
	if err := reload(db, cfg); err != nil {
		log.Printf("warning: initial load failed: %v", err)
	}

	// Reload on SIGHUP.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGHUP)
	go func() {
		for range sigs {
			if err := reload(db, cfg); err != nil {
				log.Printf("reload error: %v", err)
			}
		}
	}()

	if err := RunServer(cfg.SocketPath, db); err != nil {
		log.Fatalf("server: %v", err)
	}
}

func reload(db *UserDB, cfg *Config) error {
	principals, err := LoadPrincipals(cfg.AuthIDPath)
	if err != nil {
		return err
	}
	db.Rebuild(principals, cfg)
	log.Printf("loaded %d principals from %s", len(principals), cfg.AuthIDPath)
	return nil
}
