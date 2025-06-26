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

//go:build integration

// Package integration contains integration tests.
//
// These tests test opkssh e2e using external dependencies.
package integration

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"golang.org/x/crypto/ssh"
)

const (
	// LoginCallbackServerTimeout is the amount of time to wait for the opkssh
	// login callback server to startup
	LoginCallbackServerTimeout = 5 * time.Second
)

// TestLogConsumer consumes log messages outputted by Docker containers spawned
// by testcontainers-go.
type TestLogConsumer struct {
	Msgs []string
}

// NewTestLogConsumer returns a new TestLogConsumer.
func NewTestLogConsumer() *TestLogConsumer {
	return &TestLogConsumer{
		Msgs: []string{},
	}
}

// Accept appends the log message to an internal buffer.
func (g *TestLogConsumer) Accept(l testcontainers.Log) {
	g.Msgs = append(g.Msgs, string(l.Content))
}

// Dump returns all collected log messages from stdout or stderr
func (g *TestLogConsumer) Dump() string {
	return strings.Join(g.Msgs, "")
}

// WaitForServer waits for an HTTP server running at url to start within the
// supplied timeout.
func WaitForServer(ctx context.Context, url string, timeout time.Duration) error {
	ch := make(chan error)
	// Create context that cancels after specified timeout
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	go func() {
		for {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				ch <- err
				return
			}

			_, err = http.DefaultClient.Do(req)
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				return
			}
			if err == nil {
				ch <- nil
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	// Wait for response or timeout
	select {
	case err := <-ch:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// GetOPKSshKey tries to find a valid OPK SSH key at one of the expected
// locations. If found, the parsed public SSH key and path to its secret key is
// returned. Otherwise, an error is returned if no valid OPK SSH key could be
// found.
func GetOPKSshKey(seckeyPath string) (ssh.PublicKey, string, error) {
	var expectedSSHSecKeyFilePaths []string
	var sshPath string

	if seckeyPath != "" {
		sshPath = filepath.Dir(seckeyPath)
		expectedSSHSecKeyFilePaths = []string{filepath.Base(seckeyPath)}

	} else {
		// Get user's SSH path
		homePath, err := os.UserHomeDir()
		if err != nil {
			return nil, "", fmt.Errorf("failed to get user's home directory: %w", err)
		}
		sshPath = filepath.Join(homePath, ".ssh")

		// Find a valid OPK SSH key at one of the expected locations
		expectedSSHSecKeyFilePaths = []string{"id_ecdsa", "id_dsa"}
	}

	var pubKey ssh.PublicKey
	var secKeyFilePath string
	for _, secKeyFilePath = range expectedSSHSecKeyFilePaths {
		secKeyFilePath = filepath.Join(sshPath, secKeyFilePath)

		// Read public key. Expected public key has suffix "-cert.pub"
		pubKeyFilePath := secKeyFilePath + "-cert.pub"
		sshPubKey, err := os.ReadFile(pubKeyFilePath)
		if err != nil {
			continue
		}

		// Parse the public key and check that it is an openpubkey SSH cert
		parsedPubKey, comment, _, _, err := ssh.ParseAuthorizedKey(sshPubKey)
		if err != nil {
			continue
		}

		// Check if it's an OPK ssh key
		if comment == "openpubkey" {
			pubKey = parsedPubKey
			break
		}
	}

	// Check to see if we find at least one OPK SSH key
	if pubKey == nil {
		return nil, "", fmt.Errorf("failed to find valid OPK public SSH key")
	}

	// Check private SSH key file exists
	if _, err := os.Stat(secKeyFilePath); err == nil {
		return pubKey, secKeyFilePath, nil
	} else if errors.Is(err, os.ErrNotExist) {
		return nil, "", fmt.Errorf("failed to find corresponding OPK private SSH key at path %s: %w", secKeyFilePath, err)
	} else {
		return nil, "", err
	}
}

// GetAvailablePort finds and returns an available TCP port to bind to on
// localhost. There is no guarantee the port remains available after this
// function returns.
func GetAvailablePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("failed to find available port: %w", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// TryFunc runs f every second until f returns nil or the context is cancelled.
// Returns the last error returned by f; otherwise, if f never had a chance to
// run (due the context being cancelled before running f at least once), then
// the context's error is returned instead.
func TryFunc(ctx context.Context, f func() error) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	var err error
	for {
		select {
		case <-ctx.Done():
			if err == nil {
				return ctx.Err()
			}
			return err
		case <-ticker.C:
			// Save error
			err = f()
			if err == nil {
				return nil
			}
		}
	}
}
