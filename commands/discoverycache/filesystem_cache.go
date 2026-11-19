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
	"strings"
	"time"

	"github.com/openpubkey/openpubkey/discover"
	"github.com/spf13/afero"
)

var jwksFileRegex = regexp.MustCompile(`^jwks-[0-9a-f]{64}$`)

const tmpFilePrefix = "tmp-"

// FilesystemDiscoveryCache stores JWKS documents below BaseDir, in one
// directory per issuer.
//
// Each file is named after the SHA-256 of its contents, and its modification
// time records when that JWKS was last fetched. Fetching an unchanged JWKS
// atomically replaces the existing file with an identical one, which only
// refreshes its modification time. The issuer's other files are deleted only
// when the provider's keys change. This keeps one file per issuer however often JWKS are fetched
// (for example when clients offer tokens with unknown key IDs, which forces a
// fresh fetch), and a file is only deleted when it is genuinely out of date.
// If a concurrent Read loses that race, it reports a cache miss and the
// reader fetches the JWKS again.
//
// Expire (opkssh cache clean) removes what Write leaves behind: interrupted
// temporary files, future-dated files and issuers that are no longer
// configured.
type FilesystemDiscoveryCache struct {
	Now     func() time.Time
	Fs      afero.Fs
	BaseDir string
	// Logf receives the two events an administrator looks for when a provider
	// is down or the cache never fills: a login served from the fallback
	// window and a JWKS that could not be written. openpubkey reports them
	// only to its own error writer, which the providers never expose, so the
	// cache logs them itself. nil discards them.
	Logf func(format string, args ...any)
	// StandardMaxAge is the age Read allows normally. A Read that allows an
	// older entry is the fallback after a failed download.
	StandardMaxAge time.Duration
}

func NewFilesystemDiscoveryCache(fs afero.Fs, baseDir string) *FilesystemDiscoveryCache {
	return NewFilesystemDiscoveryCacheWithClock(time.Now, fs, baseDir)
}

func NewFilesystemDiscoveryCacheWithClock(now func() time.Time, fs afero.Fs, baseDir string) *FilesystemDiscoveryCache {
	return &FilesystemDiscoveryCache{Now: now, Fs: fs, BaseDir: baseDir}
}

func (c *FilesystemDiscoveryCache) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
	}
}

func jwksFileName(value []byte) string {
	return fmt.Sprintf("jwks-%x", sha256.Sum256(value))
}

func (c *FilesystemDiscoveryCache) issuerDir(issuer string) string {
	issuerHash := fmt.Sprintf("%x", sha256.Sum256([]byte(issuer)))
	return filepath.Join(c.BaseDir, issuerHash, "jwks")
}

// Validate checks that BaseDir, if it already exists, is a directory that is
// not writable by group or other. A cache an unprivileged user can write to is
// a key-substitution vector: an attacker who can drop a crafted JWKS snapshot
// could have the verifier trust an attacker-controlled signing key. A missing
// BaseDir is allowed; it is created with safe permissions on first Write.
func (c *FilesystemDiscoveryCache) Validate() error {
	info, err := c.Fs.Stat(c.BaseDir)
	if errors.Is(err, iofs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to stat cache base_dir %q: %w", c.BaseDir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("cache base_dir %q is not a directory", c.BaseDir)
	}
	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("cache base_dir %q must not be group- or world-writable, got permissions %#o", c.BaseDir, perm)
	}
	if err := validateCacheOwner(c.BaseDir, info); err != nil {
		return err
	}
	return validateCacheLabel(c.BaseDir)
}

// Check verifies that an already-provisioned cache directory is safe and can
// be used by the current verification account.
func (c *FilesystemDiscoveryCache) Check() error {
	if _, err := c.Fs.Stat(c.BaseDir); errors.Is(err, iofs.ErrNotExist) {
		return fmt.Errorf("cache base_dir %q does not exist", c.BaseDir)
	} else if err != nil {
		return fmt.Errorf("failed to stat cache base_dir %q: %w", c.BaseDir, err)
	}
	return c.Validate()
}

// Read returns the most recently fetched JWKS for issuer if it was fetched no
// more than maxAge ago.
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
	var newest iofs.FileInfo
	for _, entry := range entries {
		if !entry.Mode().IsRegular() || !jwksFileRegex.MatchString(entry.Name()) {
			continue
		}
		if entry.ModTime().After(now) {
			// A future modification time can result from clock skew or
			// tampering. It must not extend the lifetime of an old key set.
			continue
		}
		if newest == nil || entry.ModTime().After(newest.ModTime()) {
			newest = entry
		}
	}
	if newest == nil || now.Sub(newest.ModTime()) > maxAge {
		return nil, discover.ErrCacheMiss
	}

	content, err := afero.ReadFile(c.Fs, filepath.Join(targetDir, newest.Name()))
	if err != nil {
		// Most likely a concurrent Write replaced it with a newer JWKS.
		return nil, discover.ErrCacheMiss
	}
	if c.StandardMaxAge > 0 && maxAge > c.StandardMaxAge {
		c.logf("Using fallback JWKS from cache for %s, fetched %s ago: the provider could not be reached or served no usable keys\n",
			issuer, now.Sub(newest.ModTime()).Round(time.Second))
	}
	return content, nil
}

// Write records that value was just fetched for issuer.
func (c *FilesystemDiscoveryCache) Write(issuer string, value []byte) error {
	err := c.write(issuer, value)
	if err != nil {
		c.logf("Failed to write JWKS cache for %s: %v\n", issuer, err)
	}
	return err
}

func (c *FilesystemDiscoveryCache) write(issuer string, value []byte) error {
	targetDir := c.issuerDir(issuer)
	if err := c.Fs.MkdirAll(targetDir, 0o750); err != nil {
		return err
	}
	name := jwksFileName(value)
	path := filepath.Join(targetDir, name)
	now := c.Now()

	tmp, err := afero.TempFile(c.Fs, targetDir, tmpFilePrefix)
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
	if err := c.Fs.Chtimes(tmpName, now, now); err != nil {
		return err
	}
	// Rename is atomic: a reader sees either the old file or the complete
	// new one, never a missing file. The JWKS is usually unchanged since
	// the last fetch, so this replaces a file with identical contents and
	// only its modification time changes.
	if err := c.Fs.Rename(tmpName, path); err != nil {
		return err
	}
	c.removeOtherFiles(targetDir, name)
	return nil
}

// removeOtherFiles deletes the issuer's JWKS files other than keep. They hold
// key sets the provider no longer serves. Temporary files are left for
// Expire, as another process may still be writing them. Errors are ignored: a
// file that is not removed here is never newer than keep, so Read does not
// use it, and Expire removes it once it is old enough.
func (c *FilesystemDiscoveryCache) removeOtherFiles(dir, keep string) {
	entries, err := afero.ReadDir(c.Fs, dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == keep || !entry.Mode().IsRegular() || !jwksFileRegex.MatchString(name) {
			continue
		}
		_ = c.Fs.Remove(filepath.Join(dir, name))
	}
}

// Invalidate is a no-op. openpubkey does not call it; when a cached key fails
// verification it fetches the JWKS again, and the Write of that fetch replaces
// the out-of-date file.
func (c *FilesystemDiscoveryCache) Invalidate(context.Context, string) error {
	return nil
}

// Expire deletes JWKS files fetched more than maxAge ago and interrupted
// temporary files older than maxAge. Future-dated files are removed because
// they would otherwise evade expiry after a system clock correction.
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
			name := entry.Name()
			if !entry.Mode().IsRegular() || (!jwksFileRegex.MatchString(name) && !strings.HasPrefix(name, tmpFilePrefix)) {
				continue
			}
			modTime := entry.ModTime()
			if !modTime.After(now) && now.Sub(modTime) <= maxAge {
				continue
			}
			if err := c.Fs.Remove(filepath.Join(targetDir, name)); err != nil && !errors.Is(err, iofs.ErrNotExist) {
				return deleted, err
			}
			deleted++
		}
	}

	return deleted, nil
}
