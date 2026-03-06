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

# entrypoint.sh — start opkssh-nssd then sshd
set -euo pipefail

# ------------------------------------------------------------------ #
# 1. Start the opkssh NSS daemon                                       #
# ------------------------------------------------------------------ #
mkdir -p /run/opkssh
/usr/sbin/opkssh-nssd &
NSS_PID=$!

# Wait up to 2 s for the socket to appear
for i in $(seq 20); do
    [ -S /run/opkssh/nss.sock ] && break
    sleep 0.1
done

if [ ! -S /run/opkssh/nss.sock ]; then
    echo "ERROR: opkssh-nssd did not create the socket in time" >&2
    exit 1
fi
echo "opkssh-nssd started (pid $NSS_PID)"

# If the NSS daemon dies, take down the whole container so the
# orchestrator restarts everything cleanly.  Poll rather than using
# `wait`, which cannot cross subshell boundaries.
(
    while kill -0 "$NSS_PID" 2>/dev/null; do sleep 2; done
    echo "opkssh-nssd exited unexpectedly — stopping container" >&2
    kill 1   # SIGTERM to PID 1 (this entrypoint) triggers container stop
) &

# ------------------------------------------------------------------ #
# 2. Generate SSH host keys if the image has none                     #
# ------------------------------------------------------------------ #
ssh-keygen -A

# ------------------------------------------------------------------ #
# 3. sshd needs its privilege-separation directory                    #
# ------------------------------------------------------------------ #
mkdir -p /run/sshd

# ------------------------------------------------------------------ #
# 4. Start sshd in the foreground (-D) with stderr logging (-e)      #
# ------------------------------------------------------------------ #
echo "Starting sshd..."
exec /usr/sbin/sshd -D -e
