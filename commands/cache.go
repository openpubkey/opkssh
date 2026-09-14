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

// CacheCmd provides functionality to interact with the disk cache
// of JWKS data.
type CacheCmd struct {
	fs afero.Fs
	// ConfigPathArg is the path to the server config file
	ConfigPathArg string
}

func NewCacheCmd() *CacheCmd {
	return &CacheCmd{}
}

func (c *CacheCmd) CobraCommand() *cobra.Command {
	defaultConfigPath := filepath.Join(policy.GetSystemConfigBasePath(), "config.yml")

	cacheCmd := &cobra.Command{
		Use:   "cache",
		Short: "Commands to interact with the JWKS cache used by opkssh verify",
		Args:  cobra.NoArgs,
	}
	cacheCmd.PersistentFlags().StringVar(&c.ConfigPathArg, "config-path", defaultConfigPath, fmt.Sprintf("Path to the server config file. Default: %s", defaultConfigPath))

	cleanupCmd := &cobra.Command{
		Use:   "clean",
		Short: "Clean up all stale cache entries",
		Long: `Clean deletes all cache entries older than the given age.

If no max age is specified on the command line, then entries will be deleted if they are older than the fallback_max_age in the server configuration file (or twice the standard max_age if no fallback is configured explicitly).

This command would typically be run regularly as a cron job (running as the opkssh user) in order to prevent the cache from growing excessively over time.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			var maxAge time.Duration = 0
			if len(args) > 0 {
				maxAge, err = time.ParseDuration(args[0])
				if err != nil {
					return err
				}
			}
			return c.Expire(cmd.Context(), maxAge)
		},
	}

	cacheCmd.AddCommand(cleanupCmd)
	return cacheCmd
}

func (c *CacheCmd) loadServerConfig() (*config.ServerConfig, error) {
	vc := NewVerifyCmd(func(username string, pkt *pktoken.PKToken, userInfo string, sshCert string, keyType string, denyList policy.DenyList, extraArgs []string) error {
		return nil
	}, c.ConfigPathArg)
	c.fs = vc.Fs
	return vc.ReadFromServerConfig()
}

func (c *CacheCmd) Expire(ctx context.Context, maxAge time.Duration) error {
	cfg, err := c.loadServerConfig()
	if err != nil {
		return fmt.Errorf("error loading server config: %v", err)
	}
	cache := cfg.CreateCache(c.fs)
	if fsCache, ok := cache.(*discoverycache.FilesystemDiscoveryCache); ok {
		if maxAge == 0 {
			// no explicit age specified, use fallback max age from config
			maxAge = cfg.CacheConfig.FallbackMaxAge
		}
		_, err := fsCache.Expire(ctx, maxAge)
		return err
	}
	return errors.New("no cache configured in server config")
}
