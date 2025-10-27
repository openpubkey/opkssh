# NSS Module for OPKSSH JIT User Provisioning

This NSS (Name Service Switch) module enables Just-In-Time (JIT) user provisioning for opkssh by making OpenSSH believe that users exist before they are actually created on the system.

## How It Works

1. When a user attempts to SSH to the server, OpenSSH checks if the user exists
2. This NSS module responds that the user exists (with temporary UID/GID)
3. OpenSSH proceeds to call AuthorizedKeysCommand (opkssh verify)
4. opkssh verifies the user's credentials and creates the actual Linux user
5. The SSH session is established with the newly created user

## Building

```bash
cd nss
make
```

This will create `libnss_opkssh.so.2`.

## Installation

The install script automatically handles installation. For manual installation:

```bash
cd nss
sudo make install
```

Then configure `/etc/nsswitch.conf` to use the module (see Configuration section).

## Configuration

### 1. Enable the NSS Module

Create `/etc/opk/nss-opkssh.conf`:

```
# Enable the NSS module for JIT user provisioning
enabled true

# UID to report for virtual users (before actual creation)
# Default: 65534 (nobody)
uid 65534

# GID to report for virtual users (before actual creation)  
# Default: 65534 (nogroup)
gid 65534

# Home directory prefix
# Default: /home
home_prefix /home

# Shell for users
# Default: /bin/bash
shell /bin/bash

# GECOS field
# Default: OPKSSH JIT User
gecos OPKSSH JIT User
```

### 2. Configure NSS Switch

Edit `/etc/nsswitch.conf` and add `opkssh` to the passwd line:

```
passwd:         files opkssh systemd
```

**Important**: Place `opkssh` AFTER `files` so real users are checked first.

### 3. Enable auto_provision_users in opkssh

In `/etc/opk/config.yml`:

```yaml
---
auto_provision_users: true
```

## Security Considerations

- The NSS module only reports users as existing; it doesn't grant any access
- Actual authentication and user creation still requires valid credentials through opkssh
- The module checks `/etc/passwd` first to avoid interfering with real users
- Virtual users are reported with UID/GID 65534 (nobody) until actually created

## Troubleshooting

### Check if the module is loaded

```bash
getent passwd testuser
```

If the NSS module is working, this will return information for any username.

### Verify configuration

```bash
cat /etc/opk/nss-opkssh.conf
```

Ensure `enabled true` is set.

### Test NSS module directly

```bash
# This should return user info for any username if NSS module is enabled
getent passwd nonexistentuser
```

### Check nsswitch.conf

```bash
grep passwd /etc/nsswitch.conf
```

Should show: `passwd: files opkssh ...`

## Disabling

To disable JIT user provisioning:

1. Set `enabled false` in `/etc/opk/nss-opkssh.conf`, OR
2. Remove `opkssh` from `/etc/nsswitch.conf`, OR  
3. Set `auto_provision_users: false` in `/etc/opk/config.yml`

## Technical Details

The NSS module implements these functions:
- `_nss_opkssh_getpwnam_r()` - Lookup user by name
- `_nss_opkssh_getpwuid_r()` - Lookup user by UID (returns NOTFOUND, handled by other modules)

The module is stateless and reads configuration on each lookup for security.
