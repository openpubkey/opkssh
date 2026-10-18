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

//go:build linux

package discoverycache

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
)

// CacheSELinuxType is the SELinux type that the opkssh policy module
// (opkssh.te) lets opkssh verify write to. The installer labels the cache
// directory with it.
const CacheSELinuxType = "opkssh_cache_t"

// selinuxEnabled reports whether SELinux is enabled (enforcing or
// permissive). It is a variable so tests can replace it.
var selinuxEnabled = func() bool {
	_, err := os.Stat("/sys/fs/selinux/enforce")
	return err == nil
}

// selinuxLabel returns the SELinux label of path, for example
// "system_u:object_r:var_t:s0". It is a variable so tests can replace it.
var selinuxLabel = func(path string) (string, error) {
	buf := make([]byte, 256)
	for {
		n, err := syscall.Getxattr(path, "security.selinux", buf)
		if errors.Is(err, syscall.ERANGE) {
			buf = make([]byte, len(buf)*2)
			continue
		}
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(buf[:n]), "\x00"), nil
	}
}

// validateCacheLabel checks that, when SELinux is enabled, base_dir carries
// the type opkssh verify is allowed to write to. Without it every cache read
// and write is denied, and every login silently fetches the JWKS again.
func validateCacheLabel(path string) error {
	if !selinuxEnabled() {
		return nil
	}
	label, err := selinuxLabel(path)
	if err != nil {
		return fmt.Errorf("failed to read the SELinux label of cache base_dir %q: %w", path, err)
	}
	parts := strings.Split(label, ":")
	if len(parts) < 3 {
		return fmt.Errorf("cache base_dir %q has an unexpected SELinux label %q", path, label)
	}
	if parts[2] != CacheSELinuxType {
		return fmt.Errorf("cache base_dir %q has SELinux type %s, but opkssh verify can only use a directory labelled %s. "+
			"Label it with: semanage fcontext -a -t %s '%s(/.*)?' && restorecon -R %s",
			path, parts[2], CacheSELinuxType, CacheSELinuxType, strings.ReplaceAll(path, ".", "\\."), path)
	}
	return nil
}
