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
	"fmt"
	"math/rand"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/openpubkey/openpubkey/discover"
	"github.com/spf13/afero"
)

// FilesystemDiscoveryCache is a DiscoveryCache implementation that uses a directory
// on the filesystem for its cache store.  Entries are written to the cache by
// creating files {BaseDir}/{SHA-256-of-issuer-URI}/jwks/jwks-{timestamp}-{random}
// and read back by finding the corresponding file with the latest timestamp.
// File modification times are not checked - the timestamp is the one encoded into
// the file name.
type FilesystemDiscoveryCache struct {
	// Now is the function that is called to determine the current time.  Normally
	// this would be time.Now but you may specify a different function for testing
	// purposes via NewFilesystemDiscoveryCacheWithClock
	Now func() time.Time
	// Fs is the filesystem within which data should be stored
	Fs afero.Fs
	// BaseDir is the base directory within the filesystem under which the cache
	// can be found
	BaseDir string
}

// NewFilesystemDiscoveryCache creates a cache that uses time.Now as its
// "current time" function
func NewFilesystemDiscoveryCache(fs afero.Fs, baseDir string) *FilesystemDiscoveryCache {
	return NewFilesystemDiscoveryCacheWithClock(time.Now, fs, baseDir)
}

// NewFilesystemDiscoveryCacheWithClock creates a cache that uses the specified
// function to retrieve the current time.
func NewFilesystemDiscoveryCacheWithClock(now func() time.Time, fs afero.Fs, baseDir string) *FilesystemDiscoveryCache {
	return &FilesystemDiscoveryCache{
		Now:     now,
		Fs:      fs,
		BaseDir: baseDir,
	}
}

// jwksFileRegex is the regular expression that saved cache file names will match.
// The file write timestamp is encoded into the file name as a decimal number of
// milliseconds-since-epoch
var jwksFileRegex = regexp.MustCompile("^jwks-([0-9]+)-")

// tmpFileRegex is the regular expression that temporary files created during a
// write operation will match.  The write algorithm writes the data to a temporary
// file and then atomic renames the temporary file to the final name, to avoid
// any other concurrent processes reading a partially-written file.
var tmpFileRegex = regexp.MustCompile("^tmp-([0-9]+)-")

func (c *FilesystemDiscoveryCache) Read(ctx context.Context, issuer string, maxAge time.Duration) ([]byte, error) {
	issuerHash := fmt.Sprintf("%x", sha256.Sum256([]byte(issuer)))
	targetDir := filepath.Join(c.BaseDir, issuerHash, "jwks")
	info, err := c.Fs.Stat(targetDir)
	if err != nil || !info.IsDir() {
		// no dir for this issuer -> empty cache
		return nil, discover.ErrCacheMiss
	}
	// we need to walk through the directory contents, which for a large cache
	// is potentially slow, so do the walk in a goroutine and abort if the context
	// is cancelled
	afs := afero.Afero{Fs: c.Fs}
	chErr := make(chan error)
	chResult := make(chan []byte)
	go func() {
		files, err := afs.ReadDir(targetDir)
		if err != nil {
			chErr <- err
			return
		}
		// ReadDir lists files in lexicographic order, so if we loop through them
		// in reverse order we'll visit the newest one first
		for i := len(files) - 1; i >= 0; i-- {
			if ctx.Err() != nil {
				// short circuit if context was cancelled
				return
			}
			fName := files[i].Name()
			match := jwksFileRegex.FindStringSubmatch(fName)
			if match != nil {
				// extract timestamp from the file name
				timestamp, err := strconv.ParseInt(match[1], 10, 64)
				if err == nil {
					if c.Now().Sub(time.UnixMilli(timestamp)) > maxAge {
						// cache entry is stale - give up now
						chErr <- discover.ErrCacheMiss
						return
					}
					// not stale, read the file and return its content
					if content, err := afs.ReadFile(filepath.Join(targetDir, fName)); err != nil {
						chErr <- err
					} else {
						chResult <- content
					}
				}
			}
		}

		// no matching files, so that's a cache miss
		chErr <- discover.ErrCacheMiss
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err = <-chErr:
		return nil, err
	case result := <-chResult:
		return result, nil
	}
}

func (c *FilesystemDiscoveryCache) Write(issuer string, value []byte) error {
	issuerHash := fmt.Sprintf("%x", sha256.Sum256([]byte(issuer)))
	targetDir := filepath.Join(c.BaseDir, issuerHash, "jwks")
	if err := c.Fs.MkdirAll(targetDir, 0755); err != nil {
		return err
	}
	now := c.Now().UnixMilli()
	// we add a random tail on the file name just in case two instances
	// happen to run at the same millisecond.  If this were ever to happen
	// we'd end up fetching the same data twice so it doesn't really matter
	// which one ends up being considered "more recent".
	tail := rand.Int31()
	tmpFileName := fmt.Sprintf("tmp-%019d-%d", now, tail)
	tmpFile := filepath.Join(targetDir, tmpFileName)
	err := afero.WriteFile(c.Fs, tmpFile, value, 0644)
	if err != nil {
		// delete the temp file - we don't care if this fails
		_ = c.Fs.Remove(tmpFile)
		return err
	}
	// atomic rename
	finalFileName := fmt.Sprintf("jwks-%019d-%d", now, tail)
	finalFile := filepath.Join(targetDir, finalFileName)
	err = c.Fs.Rename(tmpFile, finalFile)
	if err != nil {
		// delete the temp file - we don't care if this fails
		_ = c.Fs.Remove(tmpFile)
		return err
	}

	return nil
}

// Expire deletes any files from the cache that are older than maxAge
func (c *FilesystemDiscoveryCache) Expire(ctx context.Context, maxAge time.Duration) (int, error) {
	var numDeleted int = 0
	afs := afero.Afero{Fs: c.Fs}
	chErr := make(chan error)
	go func() {
		issuers, err := afs.ReadDir(c.BaseDir)
		if err != nil {
			chErr <- err
			return
		}
		for _, issDir := range issuers {
			if ctx.Err() != nil {
				// short circuit if context was cancelled
				return
			}
			if !issDir.IsDir() {
				continue
			}
			files, err := afs.ReadDir(filepath.Join(c.BaseDir, issDir.Name(), "jwks"))
			if err != nil {
				continue
			}
			for _, file := range files {
				if ctx.Err() != nil {
					// short circuit if context was cancelled
					return
				}
				fName := file.Name()
				match := jwksFileRegex.FindStringSubmatch(fName)
				if match == nil {
					match = tmpFileRegex.FindStringSubmatch(fName)
				}
				if match != nil {
					timestamp, err := strconv.ParseInt(match[1], 10, 64)
					if err == nil {
						if c.Now().Sub(time.UnixMilli(timestamp)) > maxAge {
							// cache entry is stale
							if err := c.Fs.Remove(filepath.Join(c.BaseDir, issDir.Name(), fName)); err == nil {
								numDeleted++
							}
						}
					}
				}
			}
		}
		close(chErr)
	}()

	select {
	case <-ctx.Done():
		return numDeleted, ctx.Err()
	case err := <-chErr:
		return numDeleted, err
	}
}
