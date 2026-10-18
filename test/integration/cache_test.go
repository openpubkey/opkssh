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

//go:build integration

package integration

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/melbahja/goph"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

const cacheDir = "/var/cache/opkssh"

var cacheFileRegex = regexp.MustCompile(`^/var/cache/opkssh/[0-9a-f]{64}/jwks/jwks-[0-9a-f]{64}$`)

// TestEndToEndSSHJWKSCache provisions the persistent JWKS cache with the
// installer and logs in over SSH while the OpenID provider is up, then while
// it is down. It checks that:
//   - the installer's configure_cache works on each distribution,
//   - a login writes one cache file and the next login is served from it,
//   - logins keep working from the cache when the provider is down, both
//     within max_age and, through the fallback, after it,
//   - without the fallback window the same login fails, so the previous
//     login really was served by the fallback,
//   - opkssh verify --cache=off and --cache=on override the config.
func TestEndToEndSSHJWKSCache(t *testing.T) {
	oidcContainer, authCallbackRedirectPort, serverContainer := spawnTestContainers(t)
	updateIdTokenLifetime(t, oidcContainer.Port, "1h")

	admin, err := goph.NewConn(&goph.Config{
		User:     serverContainer.User,
		Addr:     serverContainer.Host,
		Port:     uint(serverContainer.Port),
		Auth:     goph.Password(serverContainer.Password),
		Timeout:  goph.DefaultTimeout,
		Callback: ssh.InsecureIgnoreHostKey(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = admin.Close() })
	run := func(cmd string) string {
		t.Helper()
		out, err := admin.Run(cmd)
		require.NoError(t, err, "%s:\n%s", cmd, out)
		return strings.TrimSpace(string(out))
	}

	// Provision the cache with the installer, exactly as
	// OPKSSH_INSTALL_CACHE_DIR does. The images keep the installer at
	// /app/install-linux.sh, or /app/scripts/install-linux.sh on Debian.
	out := run(fmt.Sprintf(`sudo bash -c '
set -e
installer=$(ls /app/install-linux.sh /app/scripts/install-linux.sh 2>/dev/null | head -n 1)
export SHUNIT_RUNNING=1
source "$installer"
CACHE_DIR=%s
configure_cache'`, cacheDir))
	t.Logf("configure_cache:\n%s", out)
	require.Contains(t, run("sudo cat /etc/opk/config.yml"), "base_dir: "+cacheDir)
	require.Equal(t, "opksshuser 700", run("sudo stat -c '%U %a' "+cacheDir))
	require.Contains(t, run("sudo -u opksshuser /usr/local/bin/opkssh cache check"), "JWKS cache is ready")

	setCacheAges := func(maxAge, fallbackMaxAge string) {
		t.Helper()
		// tee keeps the file's owner and mode (root:opksshuser 0640).
		run(fmt.Sprintf(`printf 'cache:\n  base_dir: %s\n  max_age: %s\n  fallback_max_age: %s\n' | sudo tee /etc/opk/config.yml >/dev/null`,
			cacheDir, maxAge, fallbackMaxAge))
	}
	cacheFiles := func() []string {
		t.Helper()
		out := run("sudo find " + cacheDir + " -type f | sort")
		if out == "" {
			return nil
		}
		return strings.Split(out, "\n")
	}
	modTime := func(path string) string {
		t.Helper()
		return run("sudo stat -c %y " + path)
	}

	opkAuth := OpksshLoginAs(t, "test-user@oidc.local", "id_ecdsa_cache", oidcContainer, authCallbackRedirectPort)
	sshLogin := func() (time.Duration, error) {
		start := time.Now()
		conn, err := goph.NewConn(&goph.Config{
			User:     serverContainer.User,
			Addr:     serverContainer.Host,
			Port:     uint(serverContainer.Port),
			Auth:     opkAuth,
			Timeout:  60 * time.Second,
			Callback: ssh.InsecureIgnoreHostKey(),
		})
		if err != nil {
			return time.Since(start), err
		}
		defer conn.Close()
		out, err := conn.Run("whoami")
		if err != nil {
			return time.Since(start), err
		}
		if got := strings.TrimSpace(string(out)); got != serverContainer.User {
			return time.Since(start), fmt.Errorf("logged in as %q, want %q", got, serverContainer.User)
		}
		return time.Since(start), nil
	}

	t.Log("Provider up: the first login fetches the JWKS and writes one cache file")
	setCacheAges("1h", "2h")
	_, err = sshLogin()
	require.NoError(t, err)
	files := cacheFiles()
	require.Len(t, files, 1, "expected exactly one cache file, got %v", files)
	require.Regexp(t, cacheFileRegex, files[0])
	firstFile, firstModTime := files[0], modTime(files[0])

	t.Log("Provider up: the next login within max_age is served from the cache")
	time.Sleep(1100 * time.Millisecond)
	_, err = sshLogin()
	require.NoError(t, err)
	require.Equal(t, []string{firstFile}, cacheFiles())
	require.Equal(t, firstModTime, modTime(firstFile),
		"a cache hit must not fetch the JWKS again, so the file must not be rewritten")

	t.Log("Provider down: a login within max_age is still served from the cache")
	stopTimeout := time.Second
	require.NoError(t, oidcContainer.Stop(TestCtx, &stopTimeout))
	_, err = sshLogin()
	require.NoError(t, err)

	t.Log("Provider down: after max_age, the login falls back to the cached JWKS")
	setCacheAges("1s", "1h")
	time.Sleep(2 * time.Second)
	elapsed, err := sshLogin()
	require.NoError(t, err, "expected the fallback to accept the cached JWKS")
	// Each request to the provider times out after 10s, and sshd drops the
	// connection after LoginGraceTime (120s by default).
	require.Less(t, elapsed, 60*time.Second, "the fallback must be reached well within LoginGraceTime")
	t.Logf("Fallback login took %v", elapsed)

	t.Log("Provider down, no fallback window: the same login must fail")
	setCacheAges("1s", "1s")
	_, err = sshLogin()
	require.Error(t, err, "without a fallback window the login must fail, or the previous login was not served by the fallback")

	require.Equal(t, []string{firstFile}, cacheFiles(), "the cache must still hold exactly the one file")

	// opkssh verify --cache overrides the config, for debugging. Run verify
	// directly, as sshd would, with the provider still down.
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)
	certKey, _, err := GetOPKSshKey(filepath.Join(homeDir, ".ssh", "id_ecdsa_cache"))
	require.NoError(t, err)
	certB64 := base64.StdEncoding.EncodeToString(certKey.Marshal())
	verify := func(mode string) error {
		t.Helper()
		out, err := admin.Run(fmt.Sprintf("sudo -u opksshuser /usr/local/bin/opkssh verify --cache=%s %s %s %s",
			mode, serverContainer.User, certB64, certKey.Type()))
		if err != nil {
			return fmt.Errorf("%w: %s", err, out)
		}
		return nil
	}
	lastLogLine := func(substr string) string {
		t.Helper()
		return run(fmt.Sprintf("sudo grep -F -e %q /var/log/opkssh.log | tail -n 1", substr))
	}

	t.Log("--cache=off: ignores a cache config that would accept the login")
	setCacheAges("1h", "2h")
	require.NoError(t, verify("auto"), "with the provider down, --cache=auto must accept the login from the cache")
	require.Error(t, verify("off"), "--cache=off must not use the cache")
	require.Contains(t, lastLogLine("Persistent JWKS cache"), "Persistent JWKS cache off (--cache=off)")

	t.Log("--cache=on: uses the cache even though the config has none")
	run("printf 'deny_users: []\\n' | sudo tee /etc/opk/config.yml >/dev/null")
	require.Error(t, verify("auto"), "without a cache config, --cache=auto must not use the cache")
	require.NoError(t, verify("on"), "--cache=on must use "+cacheDir+" with the default ages")
	require.Contains(t, lastLogLine("Persistent JWKS cache"), "Persistent JWKS cache on (--cache=on): "+cacheDir)

	t.Log("An invalid --cache value fails verification and says why")
	err = verify("yes")
	require.Error(t, err)
	require.Contains(t, lastLogLine("--cache value"), `invalid --cache value "yes"`)
}
