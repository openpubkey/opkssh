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
	"crypto/sha256"
	"errors"
	"fmt"
	iofs "io/fs"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/openpubkey/openpubkey/discover"
	"github.com/spf13/afero"
)

var jwksFileRegex = regexp.MustCompile(`^jwks-([0-9]{19})-[A-Za-z0-9._-]+$`)
var tmpFileRegex = regexp.MustCompile(`^tmp-([0-9]{19})-[A-Za-z0-9._-]+$`)

// FilesystemDiscoveryCache stores immutable JWKS snapshots below BaseDir. Cache
// entries are only removed by Expire so parallel verifier invocations never
// delete an entry another invocation may be reading.
type FilesystemDiscoveryCache struct {
	Now     func() time.Time
	Fs      afero.Fs
	BaseDir string
}

func NewFilesystemDiscoveryCache(fs afero.Fs, baseDir string) *FilesystemDiscoveryCache {
	return NewFilesystemDiscoveryCacheWithClock(time.Now, fs, baseDir)
}

func NewFilesystemDiscoveryCacheWithClock(now func() time.Time, fs afero.Fs, baseDir string) *FilesystemDiscoveryCache {
	return &FilesystemDiscoveryCache{Now: now, Fs: fs, BaseDir: baseDir}
}

func (c *FilesystemDiscoveryCache) issuerDir(issuer string) string {
	issuerHash := fmt.Sprintf("%x", sha256.Sum256([]byte(issuer)))
	return filepath.Join(c.BaseDir, issuerHash, "jwks")
}

func cacheTimestamp(fileName string, expression *regexp.Regexp) (time.Time, bool) {
	match := expression.FindStringSubmatch(fileName)
	if match == nil {
		return time.Time{}, false
	}
	millis, err := strconv.ParseInt(match[1], 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.UnixMilli(millis), true
}

func (c *FilesystemDiscoveryCache) Read(ctx context.Context, issuer string, maxAge time.Duration) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	targetDir := c.issuerDir(issuer)
	entries, err := afero.ReadDir(c.Fs, targetDir)
	if err != nil {
		return nil, discover.ErrCacheMiss
	}

	now := c.Now()
	for i := len(entries) - 1; i >= 0; i-- {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		entry := entries[i]
		if entry.IsDir() {
			continue
		}
		timestamp, ok := cacheTimestamp(entry.Name(), jwksFileRegex)
		if !ok {
			continue
		}
		if timestamp.After(now) {
			// A future entry can result from clock skew or tampering. It must
			// not extend the lifetime of an old key set.
			continue
		}
		if now.Sub(timestamp) > maxAge {
			// Entries are timestamp-sorted, so every remaining valid cache
			// entry is at least as old as this one.
			return nil, discover.ErrCacheMiss
		}

		content, err := afero.ReadFile(c.Fs, filepath.Join(targetDir, entry.Name()))
		if err != nil {
			// Ignore a concurrently removed or corrupt snapshot and try an
			// older usable entry.
			continue
		}
		return content, nil
	}

	return nil, discover.ErrCacheMiss
}

func (c *FilesystemDiscoveryCache) Write(issuer string, value []byte) error {
	targetDir := c.issuerDir(issuer)
	if err := c.Fs.MkdirAll(targetDir, 0o750); err != nil {
		return err
	}

	now := c.Now().UnixMilli()
	tmp, err := afero.TempFile(c.Fs, targetDir, fmt.Sprintf("tmp-%019d-", now))
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = c.Fs.Remove(tmpName) }()

	if err := c.Fs.Chmod(tmpName, 0o640); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(value); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	finalName := filepath.Join(targetDir, fmt.Sprintf("jwks-%019d-%s", now, filepath.Base(tmpName)))
	return c.Fs.Rename(tmpName, finalName)
}

// Invalidate intentionally does not remove persistent cache entries. Verification
// processes may run concurrently; opkssh cache clean owns deletion instead.
func (c *FilesystemDiscoveryCache) Invalidate(context.Context, string) error {
	return nil
}

// Expire deletes cache snapshots and interrupted temporary files older than
// maxAge. Future-dated files are removed because they would otherwise evade
// expiry after a system clock correction.
func (c *FilesystemDiscoveryCache) Expire(ctx context.Context, maxAge time.Duration) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	issuers, err := afero.ReadDir(c.Fs, c.BaseDir)
	if errors.Is(err, iofs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}

	now := c.Now()
	deleted := 0
	for _, issuer := range issuers {
		if err := ctx.Err(); err != nil {
			return deleted, err
		}
		if !issuer.IsDir() {
			continue
		}

		targetDir := filepath.Join(c.BaseDir, issuer.Name(), "jwks")
		entries, err := afero.ReadDir(c.Fs, targetDir)
		if errors.Is(err, iofs.ErrNotExist) {
			continue
		}
		if err != nil {
			return deleted, err
		}
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return deleted, err
			}
			if entry.IsDir() {
				continue
			}
			timestamp, ok := cacheTimestamp(entry.Name(), jwksFileRegex)
			if !ok {
				timestamp, ok = cacheTimestamp(entry.Name(), tmpFileRegex)
			}
			if !ok || (!timestamp.After(now) && now.Sub(timestamp) <= maxAge) {
				continue
			}
			if err := c.Fs.Remove(filepath.Join(targetDir, entry.Name())); err != nil && !errors.Is(err, iofs.ErrNotExist) {
				return deleted, err
			}
			deleted++
		}
	}

	return deleted, nil
}
