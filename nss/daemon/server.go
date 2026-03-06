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
	"encoding/json"
	"log"
	"net"
	"os"
)

type request struct {
	Op   string `json:"op"`
	Name string `json:"name,omitempty"`
	UID  uint32 `json:"uid,omitempty"`
}

type response struct {
	Found bool   `json:"found"`
	Name  string `json:"name,omitempty"`
	UID   uint32 `json:"uid,omitempty"`
	GID   uint32 `json:"gid,omitempty"`
	Gecos string `json:"gecos,omitempty"`
	Dir   string `json:"dir,omitempty"`
	Shell string `json:"shell,omitempty"`
}

// shadowResponse is the wire format for shadow (spwd) entries.
// All long fields use -1 to indicate "not set / never expires", matching
// the conventions of struct spwd.  We always serialise the numeric fields
// so the C parser can find them by key without special-casing the not-found
// case (the C code checks "found" first and returns NOTFOUND immediately).
type shadowResponse struct {
	Found  bool   `json:"found"`
	Name   string `json:"name,omitempty"`
	Passwd string `json:"passwd,omitempty"`
	Lstchg int64  `json:"lstchg"`
	Min    int64  `json:"min"`
	Max    int64  `json:"max"`
	Warn   int64  `json:"warn"`
	Inact  int64  `json:"inact"`
	Expire int64  `json:"expire"`
	Flag   uint64 `json:"flag"`
}

func entryToShadowResponse(e *UserEntry) shadowResponse {
	if e == nil {
		return shadowResponse{Found: false}
	}
	// Synthesise a locked, non-expiring shadow entry for the JIT user.
	// sp_pwdp = "!" → password login impossible (OIDC only).
	// All long fields = -1 → no constraints, account never expires.
	return shadowResponse{
		Found:  true,
		Name:   e.Name,
		Passwd: "!",
		Lstchg: -1,
		Min:    -1,
		Max:    -1,
		Warn:   -1,
		Inact:  -1,
		Expire: -1,
		Flag:   0,
	}
}

func entryToResponse(e *UserEntry) response {
	if e == nil {
		return response{Found: false}
	}
	return response{
		Found: true,
		Name:  e.Name,
		UID:   e.UID,
		GID:   e.GID,
		Gecos: e.Gecos,
		Dir:   e.Dir,
		Shell: e.Shell,
	}
}

// RunServer listens on the Unix socket and serves NSS queries.
func RunServer(socketPath string, db *UserDB) error {
	// Remove stale socket
	os.Remove(socketPath)

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	defer ln.Close()

	// World-readable so any process (including unprivileged ssh children) can query.
	if err := os.Chmod(socketPath, 0666); err != nil {
		return err
	}

	log.Printf("opkssh-nssd listening on %s", socketPath)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go handleConn(conn, db)
	}
}

func handleConn(conn net.Conn, db *UserDB) {
	defer conn.Close()

	scanner := bufio.NewScanner(conn)
	if !scanner.Scan() {
		return
	}

	var req request
	if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
		log.Printf("bad request: %v", err)
		return
	}

	enc := json.NewEncoder(conn)

	switch req.Op {
	case "getpwnam":
		enc.Encode(entryToResponse(db.GetByName(req.Name)))

	case "getpwuid":
		enc.Encode(entryToResponse(db.GetByUID(req.UID)))

	case "list":
		for _, e := range db.List() {
			if err := enc.Encode(entryToResponse(e)); err != nil {
				return
			}
		}

	// Shadow ops — used by the NSS shadow module so pam_unix.so can perform
	// a real account-validity check instead of returning PAM_IGNORE.
	case "getspnam":
		enc.Encode(entryToShadowResponse(db.GetByName(req.Name)))

	case "listsp":
		for _, e := range db.List() {
			if err := enc.Encode(entryToShadowResponse(e)); err != nil {
				return
			}
		}

	default:
		log.Printf("unknown op: %q", req.Op)
	}
}
