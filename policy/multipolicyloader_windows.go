//go:build windows
// +build windows

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

package policy

import (
	"fmt"
)

// ReadWithSudoScript on Windows does not use sudo (which doesn't exist).
// On Windows, the sshd service runs as LocalSystem which has full access to
// read user home directories, so we don't need privilege escalation.
// This function just returns an error indicating home policy reading failed
// and we should rely on the system policy.
func ReadWithSudoScript(h *HomePolicyLoader, username string) ([]byte, error) {
	return nil, fmt.Errorf("home policy file not supported on Windows, will use system policy only")
}
