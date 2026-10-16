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

package commands

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/openpubkey/openpubkey/discover"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/opkssh/commands/config"
	"github.com/openpubkey/opkssh/commands/discoverycache"
	"github.com/openpubkey/opkssh/policy"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
)

// CacheCmd manages the persistent JWKS cache used by opkssh verify.
type CacheCmd struct {
	fs afero.Fs
	// ConfigPathArg is the path to the server config file.
	ConfigPathArg string
}

func NewCacheCmd() *CacheCmd {
	return &CacheCmd{}
}

func (c *CacheCmd) CobraCommand() *cobra.Command {
	defaultConfigPath := filepath.Join(policy.GetSystemConfigBasePath(), "config.yml")
	cacheCmd := &cobra.Command{
		Use:   "cache",
		Short: "Manage the JWKS cache used by opkssh verify",
		Args:  cobra.NoArgs,
	}
	cacheCmd.PersistentFlags().StringVar(&c.ConfigPathArg, "config-path", defaultConfigPath, fmt.Sprintf("Path to the server config file. Default: %s", defaultConfigPath))

	cleanCmd := &cobra.Command{
		Use:   "clean [max-age]",
		Short: "Remove stale JWKS cache entries",
		Long: `Clean removes cache entries older than max-age.

Without max-age, clean uses fallback_max_age from the server configuration.
Run this command periodically as the verification user to bound cache disk use.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			maxAge := time.Duration(0)
			useConfiguredAge := true
			if len(args) == 1 {
				parsed, err := time.ParseDuration(args[0])
				if err != nil {
					return err
				}
				maxAge = parsed
				useConfiguredAge = false
			}

			deleted, err := c.expire(cmd.Context(), maxAge, useConfiguredAge)
			if errors.Is(err, ErrNoCacheConfigured) {
				// Running on a schedule against a host that has not opted in to
				// caching must not be a hard failure, or every such host emits a
				// cron error. Report it and exit successfully.
				_, err = fmt.Fprintln(cmd.OutOrStdout(), "No persistent JWKS cache configured; nothing to clean.")
				return err
			}
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Removed %d stale JWKS cache entries.\n", deleted)
			return err
		},
	}

	checkCmd := &cobra.Command{
		Use:   "check",
		Short: "Check whether the JWKS cache is ready to use",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cache, cacheCfg, err := c.filesystemCache()
			if errors.Is(err, ErrNoCacheConfigured) {
				_, writeErr := fmt.Fprintln(cmd.OutOrStdout(), "No persistent JWKS cache configured.")
				return writeErr
			}
			if err != nil {
				return err
			}
			if err := cache.Check(); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "JWKS cache is ready: %s (max age %s, fallback %s).\n", cache.BaseDir, cacheCfg.StandardMaxAge, cacheCfg.FallbackMaxAge)
			return err
		},
	}

	cacheCmd.AddCommand(cleanCmd)
	cacheCmd.AddCommand(checkCmd)
	return cacheCmd
}

func (c *CacheCmd) loadServerConfig() (*config.ServerConfig, error) {
	verifyCmd := NewVerifyCmd(func(string, *pktoken.PKToken, string, string, string, policy.DenyList, []string) error {
		return nil
	}, c.ConfigPathArg)
	c.fs = verifyCmd.Fs
	return verifyCmd.ReadFromServerConfig()
}

// ErrNoCacheConfigured is returned by expire when no persistent JWKS cache is
// configured. Callers that run on a schedule (e.g. a systemd timer) should
// treat this as a benign no-op rather than a failure.
var ErrNoCacheConfigured = errors.New("no persistent JWKS cache configured")

func (c *CacheCmd) expire(ctx context.Context, maxAge time.Duration, useConfiguredAge bool) (int, error) {
	cache, cacheCfg, err := c.filesystemCache()
	if err != nil {
		return 0, err
	}
	if useConfiguredAge && maxAge == 0 {
		maxAge = cacheCfg.FallbackMaxAge
	}
	return cache.Expire(ctx, maxAge)
}

func (c *CacheCmd) filesystemCache() (*discoverycache.FilesystemDiscoveryCache, discover.DiscoveryCacheConfig, error) {
	cfg, err := c.loadServerConfig()
	if err != nil {
		return nil, discover.DiscoveryCacheConfig{}, fmt.Errorf("load server config: %w", err)
	}
	cacheCfg, err := cfg.Cache.DiscoveryCacheConfig(c.fs)
	if err != nil {
		return nil, discover.DiscoveryCacheConfig{}, err
	}
	cache, ok := cacheCfg.Cache.(*discoverycache.FilesystemDiscoveryCache)
	if !ok {
		return nil, discover.DiscoveryCacheConfig{}, ErrNoCacheConfigured
	}
	return cache, cacheCfg, nil
}
