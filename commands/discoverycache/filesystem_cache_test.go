package discoverycache

import (
	"context"
	"fmt"
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

	futureName := fmt.Sprintf("jwks-%019d-future", now.Add(time.Hour).UnixMilli())
	require.NoError(t, afero.WriteFile(fs, cache.issuerDir(issuer)+"/"+futureName, []byte("future"), 0o640))

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
	// Guards against the Write filename format and the parsing regexes drifting
	// apart, which would silently turn every entry into a permanent cache miss.
	fs := afero.NewMemMapFs()
	now := time.UnixMilli(1_700_000_000_000)
	cache := NewFilesystemDiscoveryCacheWithClock(func() time.Time { return now }, fs, "/cache")
	issuer := "https://issuer.example"
	require.NoError(t, cache.Write(issuer, []byte("keys")))

	entries, err := afero.ReadDir(fs, cache.issuerDir(issuer))
	require.NoError(t, err)
	require.Len(t, entries, 1)

	ts, ok := cacheTimestamp(entries[0].Name(), jwksFileRegex)
	require.True(t, ok, "written filename %q did not match jwksFileRegex", entries[0].Name())
	require.Equal(t, now.UnixMilli(), ts.UnixMilli())
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
