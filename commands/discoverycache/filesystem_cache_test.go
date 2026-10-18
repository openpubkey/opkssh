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

package discoverycache

import (
	"context"
	"fmt"
	iofs "io/fs"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openpubkey/openpubkey/discover"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

func TestFilesystemDiscoveryCacheReadWriteAndExpire(t *testing.T) {
	fs := afero.NewMemMapFs()
	now := time.UnixMilli(1_000_000)
	cache := NewFilesystemDiscoveryCacheWithClock(func() time.Time { return now }, fs, "/cache")

	require.NoError(t, cache.Write("https://issuer.example", []byte("initial")))
	content, err := cache.Read(context.Background(), "https://issuer.example", time.Minute)
	require.NoError(t, err)
	require.Equal(t, []byte("initial"), content)

	now = now.Add(2 * time.Minute)
	_, err = cache.Read(context.Background(), "https://issuer.example", time.Minute)
	require.ErrorIs(t, err, discover.ErrCacheMiss)

	deleted, err := cache.Expire(context.Background(), time.Minute)
	require.NoError(t, err)
	require.Equal(t, 1, deleted)
	_, err = cache.Read(context.Background(), "https://issuer.example", time.Hour)
	require.ErrorIs(t, err, discover.ErrCacheMiss)
}

func TestFilesystemDiscoveryCacheIgnoresAndCleansFutureEntries(t *testing.T) {
	fs := afero.NewMemMapFs()
	now := time.UnixMilli(1_000_000)
	cache := NewFilesystemDiscoveryCacheWithClock(func() time.Time { return now }, fs, "/cache")
	issuer := "https://issuer.example"
	require.NoError(t, cache.Write(issuer, []byte("current")))

	futurePath := filepath.Join(cache.issuerDir(issuer), jwksFileName([]byte("future")))
	require.NoError(t, afero.WriteFile(fs, futurePath, []byte("future"), 0o640))
	require.NoError(t, fs.Chtimes(futurePath, now.Add(time.Hour), now.Add(time.Hour)))

	content, err := cache.Read(context.Background(), issuer, time.Minute)
	require.NoError(t, err)
	require.Equal(t, []byte("current"), content)

	deleted, err := cache.Expire(context.Background(), time.Hour)
	require.NoError(t, err)
	require.Equal(t, 1, deleted)
}

func TestFilesystemDiscoveryCacheHonorsCancelledContext(t *testing.T) {
	fs := afero.NewMemMapFs()
	cache := NewFilesystemDiscoveryCache(fs, "/cache")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := cache.Read(ctx, "https://issuer.example", time.Hour)
	require.ErrorIs(t, err, context.Canceled)
	deleted, err := cache.Expire(ctx, time.Hour)
	require.Zero(t, deleted)
	require.ErrorIs(t, err, context.Canceled)
}

func TestFilesystemDiscoveryCacheWrittenFilenameMatchesRegex(t *testing.T) {
	// Guards against the Write filename format and the parsing regex drifting
	// apart, which would silently turn every entry into a permanent cache miss.
	fs := afero.NewMemMapFs()
	now := time.UnixMilli(1_700_000_000_000)
	cache := NewFilesystemDiscoveryCacheWithClock(func() time.Time { return now }, fs, "/cache")
	issuer := "https://issuer.example"
	require.NoError(t, cache.Write(issuer, []byte("keys")))

	entries, err := afero.ReadDir(fs, cache.issuerDir(issuer))
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.Regexp(t, jwksFileRegex, entries[0].Name())
	require.Equal(t, jwksFileName([]byte("keys")), entries[0].Name())
	require.True(t, entries[0].ModTime().Equal(now))
}

func TestFilesystemDiscoveryCacheUnchangedJWKSRefreshesModTime(t *testing.T) {
	fs := afero.NewMemMapFs()
	now := time.UnixMilli(1_700_000_000_000)
	cache := NewFilesystemDiscoveryCacheWithClock(func() time.Time { return now }, fs, "/cache")
	issuer := "https://issuer.example"
	dir := cache.issuerDir(issuer)

	require.NoError(t, cache.Write(issuer, []byte("keys")))
	now = now.Add(50 * time.Minute)
	require.NoError(t, cache.Write(issuer, []byte("keys")))

	entries, err := afero.ReadDir(fs, dir)
	require.NoError(t, err)
	require.Len(t, entries, 1, "an unchanged JWKS must not create a second file")
	require.True(t, entries[0].ModTime().Equal(now), "an unchanged JWKS must count as freshly fetched")

	// 50 minutes after the first fetch but 10 after the second: still fresh.
	now = now.Add(10 * time.Minute)
	content, err := cache.Read(context.Background(), issuer, time.Hour)
	require.NoError(t, err)
	require.Equal(t, []byte("keys"), content)
}

func TestFilesystemDiscoveryCacheChangedJWKSReplacesOldFile(t *testing.T) {
	fs := afero.NewMemMapFs()
	now := time.UnixMilli(1_700_000_000_000)
	cache := NewFilesystemDiscoveryCacheWithClock(func() time.Time { return now }, fs, "/cache")
	issuer := "https://issuer.example"
	other := "https://other.example"
	dir := cache.issuerDir(issuer)

	require.NoError(t, cache.Write(other, []byte("other")))
	tmpPath := filepath.Join(dir, tmpFilePrefix+"inprogress")
	require.NoError(t, afero.WriteFile(fs, tmpPath, []byte("partial"), 0o640))

	for i := 0; i < 20; i++ {
		require.NoError(t, cache.Write(issuer, []byte(fmt.Sprintf("keys-%d", i))))
		now = now.Add(time.Second)
	}

	entries, err := afero.ReadDir(fs, dir)
	require.NoError(t, err)
	names := []string{}
	for _, e := range entries {
		names = append(names, e.Name())
	}
	require.ElementsMatch(t, []string{jwksFileName([]byte("keys-19")), tmpFilePrefix + "inprogress"}, names,
		"only the newest JWKS and another process's in-progress write may remain")

	content, err := cache.Read(context.Background(), issuer, time.Hour)
	require.NoError(t, err)
	require.Equal(t, []byte("keys-19"), content)
	content, err = cache.Read(context.Background(), other, time.Hour)
	require.NoError(t, err)
	require.Equal(t, []byte("other"), content, "other issuers must not be affected")
}

func TestFilesystemDiscoveryCacheSameInstantWritesKeepLast(t *testing.T) {
	// The clock does not advance, so every file gets the same modification
	// time. Read must still return the JWKS written last.
	fs := afero.NewMemMapFs()
	now := time.UnixMilli(1_700_000_000_000)
	cache := NewFilesystemDiscoveryCacheWithClock(func() time.Time { return now }, fs, "/cache")
	issuer := "https://issuer.example"

	for i := 0; i < 50; i++ {
		want := []byte(fmt.Sprintf("keys-%d", i))
		require.NoError(t, cache.Write(issuer, want))
		got, err := cache.Read(context.Background(), issuer, time.Hour)
		require.NoError(t, err)
		require.Equal(t, want, got, "write %d", i)
	}
}

func TestFilesystemDiscoveryCacheRewritesCorruptedFile(t *testing.T) {
	fs := afero.NewMemMapFs()
	now := time.UnixMilli(1_700_000_000_000)
	cache := NewFilesystemDiscoveryCacheWithClock(func() time.Time { return now }, fs, "/cache")
	issuer := "https://issuer.example"
	require.NoError(t, cache.Write(issuer, []byte(`{"keys":[]}`)))

	path := filepath.Join(cache.issuerDir(issuer), jwksFileName([]byte(`{"keys":[]}`)))
	require.NoError(t, afero.WriteFile(fs, path, []byte(`{"ke`), 0o640))

	require.NoError(t, cache.Write(issuer, []byte(`{"keys":[]}`)))
	content, err := afero.ReadFile(fs, path)
	require.NoError(t, err)
	require.Equal(t, []byte(`{"keys":[]}`), content, "a corrupted file must be rewritten")
}

// vanishingFs makes every JWKS file unreadable, as if each were deleted
// between listing and reading by a concurrent Write.
type vanishingFs struct{ afero.Fs }

func (v vanishingFs) Open(name string) (afero.File, error) {
	if strings.HasPrefix(filepath.Base(name), "jwks-") {
		return nil, iofs.ErrNotExist
	}
	return v.Fs.Open(name)
}

func TestFilesystemDiscoveryCacheVanishedFileIsCacheMiss(t *testing.T) {
	fs := afero.NewMemMapFs()
	now := time.UnixMilli(1_700_000_000_000)
	cache := NewFilesystemDiscoveryCacheWithClock(func() time.Time { return now }, fs, "/cache")
	issuer := "https://issuer.example"
	require.NoError(t, cache.Write(issuer, []byte("keys")))

	reader := NewFilesystemDiscoveryCacheWithClock(cache.Now, vanishingFs{Fs: fs}, "/cache")
	_, err := reader.Read(context.Background(), issuer, time.Hour)
	require.ErrorIs(t, err, discover.ErrCacheMiss, "a vanished file must be a cache miss, not an error")
}

func TestFilesystemDiscoveryCacheInvalidateDoesNotDelete(t *testing.T) {
	fs := afero.NewMemMapFs()
	cache := NewFilesystemDiscoveryCache(fs, "/cache")
	issuer := "https://issuer.example"
	require.NoError(t, cache.Write(issuer, []byte("keys")))
	require.NoError(t, cache.Invalidate(context.Background(), issuer))
	_, err := cache.Read(context.Background(), issuer, time.Hour)
	require.NoError(t, err)
}

func TestFilesystemDiscoveryCacheValidate(t *testing.T) {
	t.Run("missing base_dir is allowed", func(t *testing.T) {
		cache := NewFilesystemDiscoveryCache(afero.NewMemMapFs(), "/cache")
		require.NoError(t, cache.Validate())
	})

	t.Run("safe permissions pass", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		require.NoError(t, fs.MkdirAll("/cache", 0o750))
		cache := NewFilesystemDiscoveryCache(fs, "/cache")
		require.NoError(t, cache.Validate())
	})

	t.Run("group-writable base_dir is rejected", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		require.NoError(t, fs.MkdirAll("/cache", 0o770))
		cache := NewFilesystemDiscoveryCache(fs, "/cache")
		require.ErrorContains(t, cache.Validate(), "group- or world-writable")
	})

	t.Run("world-writable base_dir is rejected", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		require.NoError(t, fs.MkdirAll("/cache", 0o757))
		cache := NewFilesystemDiscoveryCache(fs, "/cache")
		require.ErrorContains(t, cache.Validate(), "group- or world-writable")
	})

	t.Run("base_dir that is a file is rejected", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		require.NoError(t, afero.WriteFile(fs, "/cache", []byte("x"), 0o600))
		cache := NewFilesystemDiscoveryCache(fs, "/cache")
		require.ErrorContains(t, cache.Validate(), "not a directory")
	})
}

func TestFilesystemDiscoveryCacheCheckRequiresExistingDirectory(t *testing.T) {
	cache := NewFilesystemDiscoveryCache(afero.NewMemMapFs(), "/cache")
	require.ErrorContains(t, cache.Check(), "does not exist")
}
