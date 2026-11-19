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

	"github.com/spf13/afero"

	"github.com/stretchr/testify/require"
)

func TestValidateCacheOwnerUID(t *testing.T) {
	path := t.TempDir()
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.NoError(t, validateCacheOwnerUID(path, info, os.Geteuid()))
	err = validateCacheOwnerUID(path, info, os.Geteuid()+1)
	require.ErrorContains(t, err, "is owned by "+userName(os.Geteuid())+", but this process runs as "+userName(os.Geteuid()+1))
	require.ErrorContains(t, err, "sudo -u "+userName(os.Geteuid())+" opkssh cache check")
}

func TestValidateRejectsForeignOwnerEvenAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to chown the test directory")
	}
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o700))
	require.NoError(t, os.Chown(dir, 65534, -1))

	cache := NewFilesystemDiscoveryCache(afero.NewOsFs(), dir)
	require.ErrorContains(t, cache.Validate(), "is owned by "+userName(65534)+", but this process runs as root")

	require.NoError(t, os.Chown(dir, 0, -1))
	require.NoError(t, cache.Validate())
}

func TestUserName(t *testing.T) {
	require.Equal(t, "root", userName(0))
	require.Equal(t, "uid 4294967290", userName(4294967290))
}
