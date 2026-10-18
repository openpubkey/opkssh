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

	cacheCfg, err := cfg.Cache.discoveryCacheConfig(afero.NewMemMapFs(), "linux")
	require.NoError(t, err)
	require.IsType(t, &discoverycache.FilesystemDiscoveryCache{}, cacheCfg.Cache)
	require.Equal(t, time.Hour, cacheCfg.StandardMaxAge)
	require.Equal(t, 2*time.Hour, cacheCfg.FallbackMaxAge)
}

func TestCacheConfigDiscoveryCacheConfigRejectsInvalidFallback(t *testing.T) {
	cfg, err := NewServerConfig([]byte("cache:\n  base_dir: /var/cache/opkssh\n  max_age: 2h\n  fallback_max_age: 1h\n"))
	require.NoError(t, err)

	_, err = cfg.Cache.discoveryCacheConfig(afero.NewMemMapFs(), "linux")
	require.ErrorContains(t, err, "must not be less")
}

func TestCacheConfigDiscoveryCacheConfigRejectsNegativeAges(t *testing.T) {
	cfg, err := NewServerConfig([]byte("cache:\n  base_dir: /var/cache/opkssh\n  max_age: -1h\n"))
	require.NoError(t, err)

	_, err = cfg.Cache.discoveryCacheConfig(afero.NewMemMapFs(), "linux")
	require.ErrorContains(t, err, "must not be negative")
}

func TestCacheConfigDiscoveryCacheConfigRejectsInsecureBaseDir(t *testing.T) {
	cfg, err := NewServerConfig([]byte("cache:\n  base_dir: /var/cache/opkssh\n"))
	require.NoError(t, err)

	fs := afero.NewMemMapFs()
	require.NoError(t, fs.MkdirAll("/var/cache/opkssh", 0o777))

	_, err = cfg.Cache.discoveryCacheConfig(fs, "linux")
	require.ErrorContains(t, err, "group- or world-writable")
}

func TestCacheConfigDiscoveryCacheConfigRejectsRelativeBaseDir(t *testing.T) {
	cfg, err := NewServerConfig([]byte("cache:\n  base_dir: relative/dir\n"))
	require.NoError(t, err)

	_, err = cfg.Cache.discoveryCacheConfig(afero.NewMemMapFs(), "linux")
	require.ErrorContains(t, err, "must be an absolute path")
}

func TestCacheConfigWithMode(t *testing.T) {
	configured := CacheConfig{BaseDir: "/srv/opkssh-cache", StandardMaxAge: 30 * time.Minute, FallbackMaxAge: 3 * time.Hour}

	tests := []struct {
		name    string
		in      CacheConfig
		mode    string
		want    CacheConfig
		wantErr string
	}{
		{name: "auto keeps the config", in: configured, mode: CacheModeAuto, want: configured},
		{name: "empty mode is auto", in: configured, mode: "", want: configured},
		{name: "auto with no cache stays off", in: CacheConfig{}, mode: CacheModeAuto, want: CacheConfig{}},
		{name: "off ignores the config", in: configured, mode: CacheModeOff, want: CacheConfig{}},
		{name: "on keeps configured settings", in: configured, mode: CacheModeOn, want: configured},
		{name: "on without config uses the default dir", in: CacheConfig{}, mode: CacheModeOn, want: CacheConfig{BaseDir: DefaultCacheBaseDir}},
		{name: "on keeps configured ages without base_dir", in: CacheConfig{StandardMaxAge: time.Minute}, mode: CacheModeOn,
			want: CacheConfig{BaseDir: DefaultCacheBaseDir, StandardMaxAge: time.Minute}},
		{name: "invalid mode", in: configured, mode: "yes", wantErr: `invalid --cache value "yes": want auto, on or off`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.in.WithMode(tt.mode)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestCacheConfigOffDisablesDiscoveryCache(t *testing.T) {
	cfg, err := NewServerConfig([]byte("cache:\n  base_dir: /var/cache/opkssh\n"))
	require.NoError(t, err)
	off, err := cfg.Cache.WithMode(CacheModeOff)
	require.NoError(t, err)
	cacheCfg, err := off.discoveryCacheConfig(afero.NewMemMapFs(), "linux")
	require.NoError(t, err)
	require.Nil(t, cacheCfg.Cache)
}

func TestCacheConfigUnsupportedOS(t *testing.T) {
	cfg, err := NewServerConfig([]byte("cache:\n  base_dir: /var/cache/opkssh\n"))
	require.NoError(t, err)
	_, err = cfg.Cache.discoveryCacheConfig(afero.NewMemMapFs(), "windows")
	require.ErrorContains(t, err, "the persistent JWKS cache is not supported on windows")

	// Without a cache section there is nothing to report.
	cacheCfg, err := CacheConfig{}.discoveryCacheConfig(afero.NewMemMapFs(), "windows")
	require.NoError(t, err)
	require.Nil(t, cacheCfg.Cache)
}
