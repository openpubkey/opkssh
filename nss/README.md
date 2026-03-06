# opkssh NSS module — JIT user provisioning

opkssh authenticates users via OIDC tokens embedded in SSH certificates, but
OpenSSH requires the connecting user to already exist in `/etc/passwd` (or an
NSS source) before it will invoke `AuthorizedKeysCommand`.  This prevents
just-in-time (JIT) user creation.

This directory adds a daemon-backed NSS module that solves the problem without
touching `/etc/passwd` or maintaining a separate user database:

```
sshd
 ├── getpwnam("alice")  ─→  glibc NSS  ─→  libnss_opkssh.so.2  ─→  Unix socket
 │                                                                        │
 │                                                               opkssh-nssd
 │                                                      (reads /etc/opk/auth_id)
 │
 └── AuthorizedKeysCommand: opkssh verify alice <cert> <type>
      (real OIDC token validation + policy check)
```

**Two deliverables:**

| Artefact | Language | Purpose |
|---|---|---|
| `opkssh-nssd` | Go | Daemon; reads `auth_id`, synthesises users in-memory |
| `libnss_opkssh.so.2` | C | NSS module; bridges glibc to the daemon over a Unix socket |

The module also implements the **shadow** interface (`getspnam_r`) so that
`pam_unix.so` finds a synthetic shadow entry for each JIT user and returns
`PAM_SUCCESS` — leaving the standard `/etc/pam.d/common-account` stack
completely unmodified.

---

## How it works

### UID assignment

UIDs are derived deterministically from the username using FNV-32a hashing,
mapped into a configurable range (`uid_min`–`uid_max`).  Collisions are
resolved by linear probing.  The same username always gets the same UID
regardless of order or restart.

### Shadow entries

The synthesised shadow entry for every JIT user has:

| Field | Value | Effect |
|---|---|---|
| `sp_pwdp` | `!` | Password login impossible; OIDC only |
| `sp_max` | `-1` | Password never expires |
| `sp_expire` | `-1` | Account never expires |

`pam_unix.so` sees a valid, non-expired account and returns `PAM_SUCCESS`.

### Wire protocol

Newline-delimited JSON over an AF\_UNIX stream socket.

```
→ {"op":"getpwnam","name":"alice"}
← {"found":true,"name":"alice","uid":64874,"gid":60000,"gecos":"alice (opkssh)","dir":"/home/alice","shell":"/bin/bash"}

→ {"op":"getspnam","name":"alice"}
← {"found":true,"name":"alice","passwd":"!","lstchg":-1,"min":-1,"max":-1,"warn":-1,"inact":-1,"expire":-1,"flag":0}

→ {"op":"getpwuid","uid":64874}
← {"found":true, ...}

→ {"op":"list"}      (one JSON object per line until EOF)
→ {"op":"listsp"}    (shadow variant)
```

---

## Building

Requirements: `gcc`, `make`, Go ≥ 1.21.

```bash
make -C nss all
# Produces: nss/libnss_opkssh.so.2  nss/opkssh-nssd
```

### Install

```bash
make -C nss install          # copies .so, daemon, and systemd unit
```

`make install` prints the required `/etc/nsswitch.conf` changes after
installing.

---

## Configuration

### `/etc/nsswitch.conf`

```
passwd: files opkssh
shadow: files opkssh
```

`files` first ensures local accounts (root, system users) take priority.

### `/etc/opk/nss.conf`

Copy [`example/nss.conf`](example/nss.conf) to `/etc/opk/nss.conf` and edit
as needed.  All settings are optional — the file may be absent and defaults
will be used.

### `/etc/opk/auth_id`

The same file that `opkssh verify` uses.  See [`example/auth_id`](example/auth_id).

Permissions must be `640 root:opksshuser` (or readable by the daemon's user).

### `/etc/opk/providers`

The same file that `opkssh verify` uses.  See [`example/providers`](example/providers).

---

## PAM

No PAM changes are required.  The shadow NSS module means `pam_unix.so` can
always find a shadow entry for JIT users, so the standard
`@include common-account` in `/etc/pam.d/sshd` works correctly.

To auto-create home directories on first login, add to
`/etc/pam.d/common-session`:

```
session optional pam_mkhomedir.so skel=/etc/skel umask=0022
```

---

## Systemd

```bash
systemctl daemon-reload
systemctl enable --now opkssh-nss
```

The unit file (`opkssh-nss.service`) creates `/run/opkssh/` automatically via
`RuntimeDirectory=opkssh` and applies several hardening options
(`ProtectSystem`, `NoNewPrivileges`, `PrivateTmp`).

Send `SIGHUP` to reload `auth_id` without restarting:

```bash
systemctl reload opkssh-nss
# or: kill -HUP $(pidof opkssh-nssd)
```

---

## Testing

### Unit / integration (shell)

```bash
# Docker (recommended — no system changes):
docker compose -f nss/docker-compose.test.yml run --rm tests

# Or directly on a machine that already has the daemon running:
nss/test/run_tests.sh
```

The script runs 37 tests covering `getpwnam`, `getpwuid`, `getspnam`, UID
stability, shadow field values, enumeration, SIGHUP reload, and daemon-down
fallback.

---

## Security considerations

* The socket (`/run/opkssh/nss.sock`) is world-readable (`0666`) so that
  unprivileged processes (sshd's privilege-separated children) can query it.
  The daemon serves only synthesised entries derived from `auth_id` — it never
  proxies `/etc/shadow`.

* The actual security gate remains `opkssh verify`, which validates the OIDC
  token cryptographically and checks the identity against `auth_id`/`providers`.
  The NSS module only makes the user *appear* to exist before sshd reaches that
  gate.

* JIT users have `sp_pwdp = "!"` in their shadow entry, so password
  authentication is always blocked regardless of PAM configuration.
