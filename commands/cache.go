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
Run this command periodically as the opkssh user to bound cache disk use.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				deleted, err := c.Expire(cmd.Context(), 0)
				if err != nil {
					return err
				}
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "Removed %d stale JWKS cache entries.\n", deleted)
				return err
			}

			maxAge, err := time.ParseDuration(args[0])
			if err != nil {
				return err
			}
			deleted, err := c.expire(cmd.Context(), maxAge, false)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Removed %d stale JWKS cache entries.\n", deleted)
			return err
		},
	}

	cacheCmd.AddCommand(cleanCmd)
	return cacheCmd
}

func (c *CacheCmd) loadServerConfig() (*config.ServerConfig, error) {
	verifyCmd := NewVerifyCmd(func(string, *pktoken.PKToken, string, string, string, policy.DenyList, []string) error {
		return nil
	}, c.ConfigPathArg)
	c.fs = verifyCmd.Fs
	return verifyCmd.ReadFromServerConfig()
}

// Expire removes entries older than maxAge and returns the number removed. A
// zero maxAge uses the configured fallback maximum age.
func (c *CacheCmd) Expire(ctx context.Context, maxAge time.Duration) (int, error) {
	return c.expire(ctx, maxAge, true)
}

func (c *CacheCmd) expire(ctx context.Context, maxAge time.Duration, useConfiguredAge bool) (int, error) {
	cfg, err := c.loadServerConfig()
	if err != nil {
		return 0, fmt.Errorf("load server config: %w", err)
	}
	cacheCfg, err := cfg.Cache.DiscoveryCacheConfig(c.fs)
	if err != nil {
		return 0, err
	}
	cache, ok := cacheCfg.Cache.(*discoverycache.FilesystemDiscoveryCache)
	if !ok {
		return 0, errors.New("no persistent JWKS cache configured")
	}
	if useConfiguredAge && maxAge == 0 {
		maxAge = cacheCfg.FallbackMaxAge
	}
	return cache.Expire(ctx, maxAge)
}
