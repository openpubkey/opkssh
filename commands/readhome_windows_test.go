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

//go:build windows

package commands

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadHome_InvalidUsername(t *testing.T) {
	tests := []struct {
		name     string
		username string
	}{
		{name: "empty string", username: ""},
		{name: "contains backslash", username: `DOMAIN\user`},
		{name: "contains space", username: "user name"},
		{name: "contains slash", username: "user/name"},
		{name: "shell injection", username: "user;rm -rf /"},
		{name: "path traversal", username: "../etc/passwd"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ReadHome(tt.username)
			require.Error(t, err)
			require.Contains(t, err.Error(), "not a valid Windows username")
		})
	}
}

func TestReadHome_NonexistentUser(t *testing.T) {
	_, err := ReadHome("nonexistent_user_abc123xyz")
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to find user")
}

func TestReadHome_ValidUsernameFormat(t *testing.T) {
	// These usernames are syntactically valid but the users don't exist,
	// so they should fail at user lookup, not at validation.
	tests := []struct {
		name     string
		username string
	}{
		{name: "simple", username: "testuser"},
		{name: "with dot", username: "test.user"},
		{name: "with dash", username: "test-user"},
		{name: "with underscore", username: "test_user"},
		{name: "alphanumeric", username: "user123"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ReadHome(tt.username)
			require.Error(t, err)
			// Should fail at user lookup, not validation
			require.NotContains(t, err.Error(), "not a valid Windows username")
		})
	}
}
