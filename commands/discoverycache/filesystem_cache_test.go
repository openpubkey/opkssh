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

const (
	exampleIssuer = "https://example.com"
	// exampleIssuerHash is the SHA-256 hash of exampleIssuer
	exampleIssuerHash = "100680ad546ce6a577f42f52df33b4cfdca756859e664b8d7de329b150d09ce9"
)

func TestFilesystemCache(t *testing.T) {
	fs := afero.NewMemMapFs()
	iofs := afero.NewIOFS(fs)
	afs := &afero.Afero{Fs: fs}

	curTime := time.UnixMilli(1000000)
	nowFunc := func() time.Time {
		return curTime
	}

	cache := NewFilesystemDiscoveryCacheWithClock(nowFunc, fs, "/cache-test")

	// cache is initially empty
	_, err := cache.Read(context.Background(), exampleIssuer, time.Minute)
	require.Equal(t, discover.ErrCacheMiss, err)

	originalData := "initial-keys"
	// check for initial write
	err = cache.Write(exampleIssuer, []byte(originalData))
	require.NoError(t, err)
	// there is now exactly one file in the cache for this issuer
	cacheEntries, err := iofs.Glob(fmt.Sprintf("/cache-test/%s/jwks/jwks-*", exampleIssuerHash))
	require.NoError(t, err)
	require.Len(t, cacheEntries, 1)
	content, err := afs.ReadFile(cacheEntries[0])
	require.NoError(t, err)
	require.Equal(t, originalData, string(content))

	curTime = curTime.Add(time.Minute)
	// if we query the cache for keys of max age 2 minutes then we get the cached key back
	content, err = cache.Read(context.Background(), exampleIssuer, 2*time.Minute)
	require.NoError(t, err)
	require.Equal(t, originalData, string(content))

	// but if we query for keys of max age 30 sec then we get a miss
	_, err = cache.Read(context.Background(), exampleIssuer, 30*time.Second)
	require.Equal(t, discover.ErrCacheMiss, err)

	curTime = curTime.Add(15 * time.Minute)
	// write another value later
	newData := "new-keys"
	err = cache.Write(exampleIssuer, []byte(newData))
	require.NoError(t, err)
	// there are now two files in the cache
	cacheEntries, err = iofs.Glob(fmt.Sprintf("/cache-test/%s/jwks/jwks-*", exampleIssuerHash))
	require.NoError(t, err)
	require.Len(t, cacheEntries, 2)

	curTime = curTime.Add(time.Minute)
	// if we ask for keys now then we get the newer entry
	content, err = cache.Read(context.Background(), exampleIssuer, 2*time.Minute)
	require.NoError(t, err)
	require.Equal(t, newData, string(content))
}
