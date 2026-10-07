package config

import (
	"testing"
	"time"

	"github.com/openpubkey/opkssh/commands/discoverycache"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

func TestCacheConfigDiscoveryCacheConfigDefaults(t *testing.T) {
	cfg, err := NewServerConfig([]byte("cache:\n  base_dir: /var/cache/opkssh\n"))
	require.NoError(t, err)

	cacheCfg, err := cfg.Cache.DiscoveryCacheConfig(afero.NewMemMapFs())
	require.NoError(t, err)
	require.IsType(t, &discoverycache.FilesystemDiscoveryCache{}, cacheCfg.Cache)
	require.Equal(t, time.Hour, cacheCfg.StandardMaxAge)
	require.Equal(t, 2*time.Hour, cacheCfg.FallbackMaxAge)
}

func TestCacheConfigDiscoveryCacheConfigRejectsInvalidFallback(t *testing.T) {
	cfg, err := NewServerConfig([]byte("cache:\n  base_dir: /var/cache/opkssh\n  max_age: 2h\n  fallback_max_age: 1h\n"))
	require.NoError(t, err)

	_, err = cfg.Cache.DiscoveryCacheConfig(afero.NewMemMapFs())
	require.ErrorContains(t, err, "must not be less")
}

func TestCacheConfigDiscoveryCacheConfigRejectsNegativeAges(t *testing.T) {
	cfg, err := NewServerConfig([]byte("cache:\n  base_dir: /var/cache/opkssh\n  max_age: -1h\n"))
	require.NoError(t, err)

	_, err = cfg.Cache.DiscoveryCacheConfig(afero.NewMemMapFs())
	require.ErrorContains(t, err, "must not be negative")
}

func TestCacheConfigDiscoveryCacheConfigRejectsInsecureBaseDir(t *testing.T) {
	cfg, err := NewServerConfig([]byte("cache:\n  base_dir: /var/cache/opkssh\n"))
	require.NoError(t, err)

	fs := afero.NewMemMapFs()
	require.NoError(t, fs.MkdirAll("/var/cache/opkssh", 0o777))

	_, err = cfg.Cache.DiscoveryCacheConfig(fs)
	require.ErrorContains(t, err, "group- or world-writable")
}
