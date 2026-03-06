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
	"hash/fnv"
	"sync"
)

// UserEntry is a synthesized passwd record for an opkssh principal.
type UserEntry struct {
	Name  string `json:"name"`
	UID   uint32 `json:"uid"`
	GID   uint32 `json:"gid"`
	Gecos string `json:"gecos"`
	Dir   string `json:"dir"`
	Shell string `json:"shell"`
}

// UserDB is an in-memory store of synthesized users, rebuilt from auth_id.
type UserDB struct {
	mu      sync.RWMutex
	byName  map[string]*UserEntry
	byUID   map[uint32]*UserEntry
	ordered []*UserEntry
}

func NewUserDB() *UserDB {
	return &UserDB{
		byName: make(map[string]*UserEntry),
		byUID:  make(map[uint32]*UserEntry),
	}
}

// uidForUser derives a stable UID from the username using FNV-32a.
// Collisions within the range are resolved by incrementing until a free slot is found.
func uidForUser(username string, min, max uint32, taken map[uint32]bool) uint32 {
	h := fnv.New32a()
	h.Write([]byte(username))
	base := min + (h.Sum32() % (max - min + 1))

	uid := base
	for taken[uid] {
		uid++
		if uid > max {
			uid = min
		}
		if uid == base {
			// Range exhausted — shouldn't happen with reasonable configs
			break
		}
	}
	return uid
}

// Rebuild replaces the entire user set from a list of principals.
func (db *UserDB) Rebuild(principals []string, cfg *Config) {
	byName := make(map[string]*UserEntry, len(principals))
	byUID := make(map[uint32]*UserEntry, len(principals))
	ordered := make([]*UserEntry, 0, len(principals))

	taken := make(map[uint32]bool, len(principals))

	for _, name := range principals {
		if _, exists := byName[name]; exists {
			continue // deduplicate
		}
		uid := uidForUser(name, cfg.UIDMin, cfg.UIDMax, taken)
		taken[uid] = true

		e := &UserEntry{
			Name:  name,
			UID:   uid,
			GID:   cfg.GID,
			Gecos: name + " (opkssh)",
			Dir:   cfg.HomeDir + "/" + name,
			Shell: cfg.Shell,
		}
		byName[name] = e
		byUID[uid] = e
		ordered = append(ordered, e)
	}

	db.mu.Lock()
	db.byName = byName
	db.byUID = byUID
	db.ordered = ordered
	db.mu.Unlock()
}

func (db *UserDB) GetByName(name string) *UserEntry {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return db.byName[name]
}

func (db *UserDB) GetByUID(uid uint32) *UserEntry {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return db.byUID[uid]
}

func (db *UserDB) List() []*UserEntry {
	db.mu.RLock()
	defer db.mu.RUnlock()
	out := make([]*UserEntry, len(db.ordered))
	copy(out, db.ordered)
	return out
}
