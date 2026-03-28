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

package testutil

import (
	"fmt"
	"os/user"

	"github.com/openpubkey/opkssh/policy"
)

// ValidUser is a shared test fixture representing a valid OS user.
var ValidUser = &user.User{HomeDir: "/home/foo", Username: "foo"}

// MockUserLookup implements [policy.UserLookup] for testing.
//   - Set [User] for a default user returned on any Lookup call.
//   - Set [Error] to force every Lookup call to fail.
type MockUserLookup struct {
	// User is returned on any call to Lookup() if Error is nil.
	User *user.User
	// Error, if non-nil, is returned on any call to Lookup().
	Error error
}

var _ policy.UserLookup = &MockUserLookup{}

// Lookup implements [policy.UserLookup].
func (m *MockUserLookup) Lookup(username string) (*user.User, error) {
	if m.Error != nil {
		return nil, m.Error
	}
	if m.User != nil {
		return m.User, nil
	}
	return nil, fmt.Errorf("user %q not found", username)
}
