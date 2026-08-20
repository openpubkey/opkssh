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

package integration

import (
	"context"
	"os"
	"os/signal"
	"testing"
)

// TestCtx is marked done when the `go test` binary receives an interrupt signal
// or after all tests in the integration package have finished running
var TestCtx context.Context

func TestMain(m *testing.M) {
	os.Exit(func() int {
		// Do init stuff before all integration tests. defers in this func are
		// called after all the integration tests are complete.

		// Setup global integration CTX that accepts signal interrupt
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()
		TestCtx = ctx

		// Keep every login flow in the suite away from any real ssh-agent on
		// the host: login adds the minted certificate to the agent reachable
		// via SSH_AUTH_SOCK, and these tests must never inject test keys into
		// a developer's agent.
		os.Unsetenv("SSH_AUTH_SOCK")

		return m.Run()
	}())
}
