#!/usr/bin/env bash

# Copyright 2025 OpenPubkey
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

# run_tests.sh — integration tests for nss_opkssh + opkssh-nssd
set -euo pipefail

PASS=0
FAIL=0

ok()   { echo "  [PASS] $1"; PASS=$((PASS+1)); }
fail() { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }

section() { echo; echo "=== $1 ==="; }

# ------------------------------------------------------------------ #
# Start daemon                                                         #
# ------------------------------------------------------------------ #
section "Starting opkssh-nssd"
mkdir -p /run/opkssh
/usr/sbin/opkssh-nssd &
DAEMON_PID=$!

# Capture exit code; kill daemon if still running; re-exit with original code.
cleanup() {
    local rc=$?
    [[ -n "${DAEMON_PID:-}" ]] && kill "$DAEMON_PID" 2>/dev/null || true
    exit $rc
}
trap cleanup EXIT INT TERM

# Give the daemon a moment to create the socket
for i in $(seq 10); do
    [ -S /run/opkssh/nss.sock ] && break
    sleep 0.2
done
[ -S /run/opkssh/nss.sock ] && ok "daemon socket created" || { fail "socket not created"; exit 1; }

# ------------------------------------------------------------------ #
# getpwnam — known principals                                          #
# ------------------------------------------------------------------ #
section "getpwnam: known principals"

for user in alice bob carol dave eve; do
    entry=$(getent passwd "$user" 2>/dev/null || true)
    if [[ -n "$entry" ]]; then
        ok "getpwnam($user) → $entry"
    else
        fail "getpwnam($user) returned nothing"
    fi
done

# ------------------------------------------------------------------ #
# getpwnam — unknown principal should return nothing                   #
# ------------------------------------------------------------------ #
section "getpwnam: unknown user"

entry=$(getent passwd nonexistent_jit_user 2>/dev/null || true)
if [[ -z "$entry" ]]; then
    ok "getpwnam(nonexistent) → empty (correct)"
else
    fail "getpwnam(nonexistent) returned '$entry'"
fi

# ------------------------------------------------------------------ #
# UID/GID sanity                                                       #
# ------------------------------------------------------------------ #
section "UID/GID range check"

alice_uid=$(getent passwd alice | cut -d: -f3)
alice_gid=$(getent passwd alice | cut -d: -f4)

if [[ "$alice_uid" -ge 60000 && "$alice_uid" -le 65534 ]]; then
    ok "alice UID $alice_uid is in range [60000, 65534]"
else
    fail "alice UID $alice_uid out of expected range"
fi

[[ "$alice_gid" -eq 60000 ]] && ok "alice GID is 60000" || fail "alice GID is $alice_gid (expected 60000)"

# ------------------------------------------------------------------ #
# UID stability — same user always gets the same UID                  #
# ------------------------------------------------------------------ #
section "UID stability"

uid1=$(getent passwd alice | cut -d: -f3)
uid2=$(getent passwd alice | cut -d: -f3)
[[ "$uid1" == "$uid2" ]] && ok "alice UID stable across lookups ($uid1)" || fail "alice UID changed: $uid1 → $uid2"

# ------------------------------------------------------------------ #
# getpwuid — reverse lookup                                            #
# ------------------------------------------------------------------ #
section "getpwuid (reverse lookup)"

alice_uid=$(getent passwd alice | cut -d: -f3)
rev=$(getent passwd "$alice_uid" 2>/dev/null || true)
if [[ "$rev" == alice:* ]]; then
    ok "getpwuid($alice_uid) → alice"
else
    fail "getpwuid($alice_uid) → '$rev' (expected alice:...)"
fi

# ------------------------------------------------------------------ #
# Enumeration (getpwent / getent passwd)                              #
# ------------------------------------------------------------------ #
section "passwd enumeration"

opkssh_count=$(getent passwd | grep -c "(opkssh)" || true)
if [[ "$opkssh_count" -ge 5 ]]; then
    ok "enumeration returned $opkssh_count opkssh users (expected ≥5)"
else
    fail "enumeration returned $opkssh_count opkssh users (expected ≥5)"
fi

# All known principals appear in enumeration
for user in alice bob carol dave eve; do
    if getent passwd | grep -q "^$user:"; then
        ok "$user appears in passwd enumeration"
    else
        fail "$user missing from passwd enumeration"
    fi
done

# ------------------------------------------------------------------ #
# Home directory and shell                                             #
# ------------------------------------------------------------------ #
section "home dir and shell"

alice_dir=$(getent passwd alice | cut -d: -f6)
alice_shell=$(getent passwd alice | cut -d: -f7)

[[ "$alice_dir" == "/home/alice" ]] && ok "alice home dir = /home/alice" || fail "alice home dir = $alice_dir"
[[ "$alice_shell" == "/bin/bash" ]] && ok "alice shell = /bin/bash"       || fail "alice shell = $alice_shell"

# ------------------------------------------------------------------ #
# SIGHUP reload — add a new user and reload                           #
# ------------------------------------------------------------------ #
section "SIGHUP reload"

echo "frank  frank@example.com  https://accounts.google.com" >> /etc/opk/auth_id
kill -HUP "$DAEMON_PID"
sleep 0.5

entry=$(getent passwd frank 2>/dev/null || true)
if [[ -n "$entry" ]]; then
    ok "frank visible after SIGHUP reload"
else
    fail "frank not visible after SIGHUP reload"
fi

# Remove the entry we added
sed -i '/^frank/d' /etc/opk/auth_id

# ------------------------------------------------------------------ #
# getspnam — shadow lookups for known principals                       #
# ------------------------------------------------------------------ #
section "getspnam: known principals"

for user in alice bob carol dave eve; do
    entry=$(getent shadow "$user" 2>/dev/null || true)
    if [[ -n "$entry" ]]; then
        ok "getspnam($user) → found"
    else
        fail "getspnam($user) returned nothing"
    fi
done

# ------------------------------------------------------------------ #
# getspnam — unknown principal should return nothing                   #
# ------------------------------------------------------------------ #
section "getspnam: unknown user"

entry=$(getent shadow nonexistent_jit_user 2>/dev/null || true)
if [[ -z "$entry" ]]; then
    ok "getspnam(nonexistent) → empty (correct)"
else
    fail "getspnam(nonexistent) returned '$entry'"
fi

# ------------------------------------------------------------------ #
# Shadow field validation                                              #
# ------------------------------------------------------------------ #
section "shadow field validation"

# Format: name:passwd:lstchg:min:max:warn:inact:expire:flag
alice_spwd=$(getent shadow alice)
alice_sp_pwdp=$(echo "$alice_spwd"   | cut -d: -f2)
alice_sp_max=$(echo "$alice_spwd"    | cut -d: -f5)
alice_sp_expire=$(echo "$alice_spwd" | cut -d: -f8)

[[ "$alice_sp_pwdp" == "!" ]] \
    && ok "alice sp_pwdp = '!' (locked, OIDC-only)" \
    || fail "alice sp_pwdp = '$alice_sp_pwdp' (expected '!')"

# Empty field = -1 sentinel in shadow format (never expires)
[[ -z "$alice_sp_max" ]] \
    && ok "alice sp_max is empty (-1, password never expires)" \
    || fail "alice sp_max = '$alice_sp_max' (expected empty / -1)"

[[ -z "$alice_sp_expire" ]] \
    && ok "alice sp_expire is empty (-1, account never expires)" \
    || fail "alice sp_expire = '$alice_sp_expire' (expected empty / -1)"

# ------------------------------------------------------------------ #
# Shadow enumeration (setspent / getspent)                            #
# ------------------------------------------------------------------ #
section "shadow enumeration"

opkssh_shadow_count=$(getent shadow | grep -c "^.*:!:" || true)
if [[ "$opkssh_shadow_count" -ge 5 ]]; then
    ok "shadow enumeration returned $opkssh_shadow_count '!' entries (expected ≥5)"
else
    fail "shadow enumeration returned $opkssh_shadow_count '!' entries (expected ≥5)"
fi

for user in alice bob carol dave eve; do
    if getent shadow | grep -q "^$user:"; then
        ok "$user appears in shadow enumeration"
    else
        fail "$user missing from shadow enumeration"
    fi
done

# ------------------------------------------------------------------ #
# Daemon-down fallback                                                 #
# ------------------------------------------------------------------ #
section "Fallback when daemon is down"

kill "$DAEMON_PID" 2>/dev/null
DAEMON_PID=""
sleep 0.3

# Root is in /etc/passwd — must still be resolvable even without the daemon
root_entry=$(getent passwd root 2>/dev/null || true)
if [[ "$root_entry" == root:* ]]; then
    ok "getpwnam(root) works without daemon (files fallback)"
else
    fail "getpwnam(root) failed without daemon: '$root_entry'"
fi

# Root shadow entry must also survive daemon loss
root_shadow=$(getent shadow root 2>/dev/null || true)
if [[ "$root_shadow" == root:* ]]; then
    ok "getspnam(root) works without daemon (files fallback)"
else
    fail "getspnam(root) failed without daemon: '$root_shadow'"
fi

# ------------------------------------------------------------------ #
# Summary                                                             #
# ------------------------------------------------------------------ #
echo
echo "============================="
echo " Results: $PASS passed, $FAIL failed"
echo "============================="
[[ "$FAIL" -eq 0 ]] && exit 0 || exit 1
