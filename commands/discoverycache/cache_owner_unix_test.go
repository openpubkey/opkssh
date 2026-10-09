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

//go:build !windows

package discoverycache

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateCacheOwnerUID(t *testing.T) {
	path := t.TempDir()
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.NoError(t, validateCacheOwnerUID(path, info, os.Geteuid()))
	require.ErrorContains(t, validateCacheOwnerUID(path, info, os.Geteuid()+1), "must be owned")
}
