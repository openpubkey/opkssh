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
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

func fakeSELinux(t *testing.T, enabled bool, label string, err error) {
	t.Helper()
	oldEnabled, oldLabel := selinuxEnabled, selinuxLabel
	selinuxEnabled = func() bool { return enabled }
	selinuxLabel = func(string) (string, error) { return label, err }
	t.Cleanup(func() { selinuxEnabled, selinuxLabel = oldEnabled, oldLabel })
}

func TestValidateCacheLabel(t *testing.T) {
	tests := []struct {
		name    string
		enabled bool
		label   string
		err     error
		wantErr string
	}{
		{name: "SELinux disabled", enabled: false, label: "system_u:object_r:var_t:s0"},
		{name: "labelled opkssh_cache_t", enabled: true, label: "system_u:object_r:opkssh_cache_t:s0"},
		{name: "default /var/cache label", enabled: true, label: "system_u:object_r:var_t:s0",
			wantErr: "has SELinux type var_t, but opkssh verify can only use a directory labelled opkssh_cache_t"},
		{name: "label unreadable", enabled: true, err: errors.New("operation not supported"),
			wantErr: "failed to read the SELinux label"},
		{name: "malformed label", enabled: true, label: "unlabeled", wantErr: "unexpected SELinux label"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeSELinux(t, tt.enabled, tt.label, tt.err)
			err := validateCacheLabel("/var/cache/opk.ssh")
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestValidateCacheLabelErrorShowsFix(t *testing.T) {
	fakeSELinux(t, true, "system_u:object_r:var_t:s0", nil)
	err := validateCacheLabel("/var/cache/opk.ssh")
	require.ErrorContains(t, err, `semanage fcontext -a -t opkssh_cache_t '/var/cache/opk\.ssh(/.*)?' && restorecon -R /var/cache/opk.ssh`)
}

func TestValidateChecksSELinuxLabel(t *testing.T) {
	fakeSELinux(t, true, "system_u:object_r:var_t:s0", nil)
	fs := afero.NewMemMapFs()
	require.NoError(t, fs.MkdirAll("/cache", 0o700))
	cache := NewFilesystemDiscoveryCache(fs, "/cache")
	require.ErrorContains(t, cache.Validate(), "opkssh_cache_t")

	fakeSELinux(t, true, "system_u:object_r:opkssh_cache_t:s0", nil)
	require.NoError(t, cache.Validate())
}

func TestValidateSkipsSELinuxLabelForMissingBaseDir(t *testing.T) {
	fakeSELinux(t, true, "", errors.New("must not be called"))
	cache := NewFilesystemDiscoveryCache(afero.NewMemMapFs(), "/cache")
	require.NoError(t, cache.Validate())
}

func TestSELinuxLabelReadsRealDirectory(t *testing.T) {
	// On a host with SELinux this reads a real label; elsewhere the xattr is
	// absent or unsupported. Either way it must not panic or hang.
	label, err := selinuxLabel(t.TempDir())
	t.Logf("label=%q err=%v", label, err)
}
