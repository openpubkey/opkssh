
# Installing opkssh

This document provides a detailed description of how our [install-linux.sh](install-linux.sh) script works and the security protections used.

Description of the install-linux.sh script and what variables that can be overridden by system environment variables can be found [here](install-linux-script.md)

If you just want to install opkssh you should run:

```bash
wget -qO- "https://raw.githubusercontent.com/openpubkey/opkssh/main/scripts/install-linux.sh" | sudo bash
```

## Script commands

Running `./install-linux.sh --help` will show you all available flags.

`--no-home-policy` disables configuration steps which allows opkssh see policy files in user's home directory (/home/{username}/auth_id). Try this if you are having install failures.

`--nosshd-restart` turns off the sshd restart. This is useful in some docker setups where restarting sshd can break docker.

`--install-from=FILEPATH` allows you to install the opkssh binary from a local file.
This is useful if you want to install a locally built opkssh binary.

`--install-version=VER` downloads and installs a particular release of opkssh. By default we download and install the latest release of opkssh.
> [!NOTE]
> To install versions earlier than v0.10.0, you need to run the install-linux.sh script from the specific version tag.
> This is required because SELinux Type Enforcement files are embedded in the script for versions prior to v0.9.0.
> Example for installing v0.7.0:
> ```
> wget -qO- https://raw.githubusercontent.com/openpubkey/opkssh/refs/tags/v0.7.0/scripts/install-linux.sh | sudo bash -s -- --install-version=v0.7.0
> ```

## What the script is doing

**1: Build opkssh.** Run the following from the root directory, replace GOARCH and GOOS to match with server you wish to install OPKSSH. This will generate the opkssh binary.

```bash
go build
```

**2: Copy opkssh to server.** Copy the opkssh binary you just built in the previous step to the SSH server you want to configure

```bash
scp opkssh ${USER}@${HOSTNAME}:~
```

**3: Install opkssh on server.** SSH to the server

Create the following file directory structure on the server and move the executable there:

```bash
sudo mkdir /etc/opk
sudo sudo mv ~/opkssh /usr/local/bin/opkssh
sudo chown root /usr/local/bin/opkssh
sudo chmod 755 /usr/local/bin/opkssh
```

**3: Setup policy.**

The file `/etc/opk/providers` configures what the allowed OpenID Connect providers are.

The default values for `/etc/opk/providers` are:

```bash
# Issuer Client-ID expiration-policy 
https://accounts.google.com 206584157355-7cbe4s640tvm7naoludob4ut1emii7sf.apps.googleusercontent.com 24h
https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0 096ce0a3-5e72-4da8-9c86-12924b294a01 24h
https://gitlab.com 8d8b7024572c7fd501f64374dec6bba37096783dfcd792b3988104be08cb6923 24h
```

`/etc/opk/providers` requires the following permissions (by default we create all configuration files with the correct permissions):

```bash
sudo chown root:opksshuser /etc/opk/providers
sudo chmod 640 /etc/opk/providers
```

The file `/etc/opk/auth_id` controls which users and user identities can access the server using opkssh.
If you do not have root access, you can create a new auth_id file in at ~/auth_id and use that instead.

```bash
sudo touch /etc/opk/auth_id
sudo chown root:opksshuser /etc/opk/auth_id
sudo chmod 640 /etc/opk/auth_id
sudo opkssh add {USER} {EMAIL} {ISSUER}
```

**4: Configure sshd to use opkssh.** Check which configuration file is active.

In most cases the active configuration file will be `/etc/ssh/sshd_config`.
Add the following lines to the configuration file

```bash
AuthorizedKeysCommand /usr/local/bin/opkssh verify %u %k %t
AuthorizedKeysCommandUser opksshuser
```

If `/etc/ssh/sshd_config` contains the entry `Include /etc/ssh/sshd_config.d/*.conf`,
add a new configuration file with a lower starting number than other configuration files in ` /etc/ssh/sshd_config.d/`.

For example, if the file `/etc/ssh/sshd_config.d/20-systemd-userdb.conf` exists,
create `/etc/ssh/sshd_config.d/19-opk-ssh.conf` with the lines above.
By default, the opkssh installer will create this file at `/etc/ssh/sshd_config.d/60-opk-ssh.conf`.

Verify the setting is active with

```bash
sudo sshd -T | grep authorizedkeyscommand
```

You should see

```bash
authorizedkeyscommand /usr/local/bin/opkssh verify %u %k %t
authorizedkeyscommanduser opksshuser
```

Then create the required AuthorizedKeysCommandUser and group

```bash
sudo groupadd --system opksshuser
sudo useradd -r -M -s /sbin/nologin -g opksshuser opksshuser
```

**6: Configure sudoer and SELINUX.** Configures a sudoer command so that the opkssh AuthorizedKeysCommand process can call out to the shell to run `opkssh readhome {USER}` and thereby read the policy file for the user in `/home/{USER}/.opk/auth_id`.

```bash
"opksshuser ALL=(ALL) NOPASSWD: /usr/local/bin/opkssh readhome *"
```

This config lives in `/etc/sudoers.d/opkssh` and must have the permissions `440` with root being the owner.

If SELinux is configured we need to install an SELinux module to allow opkssh to read the policy in the user's home directory. See the section about [SELinux](#manual-selinux-module-installation-and-configuration) for details.

**7: Restart sshd.**

On Ubuntu and Debian Linux:

```bash
systemctl restart ssh
```

On Redhat, centos Linux and Arch Linux:

```bash
sudo systemctl restart sshd
```

## Manual SELinux module installation and configuration

If you're running on an SELinux-enforcing system, follow these steps to manually install the `opkssh` SELinux module and manage its runtime feature toggles.

---

### 1. Build the SELinux module

With your TE policy file (e.g., `opkssh.te`), compile and package it:

```bash
checkmodule -M -m -o opkssh.mod opkssh.te
semodule_package -o opkssh.pp -m opkssh.mod
```
This creates a compiled module of `opkssh.pp`.

### 2. Install the module

Load the packaged module into your system SELinux policy:
```bash
sudo semodule -i opkssh.pp
```

To confirme the module is loaded, use:
```bash
semodule -l | grep opkssh
```
You should see `opkssh` in the output.

### 3. Manage `opkssh` SELinux feature toggles (Booleans)
The module supports optional features controlled at runtime with SELinux booleans.

**View available toggles**
```
getsebool -a | grep opkssh
```
Example output:
```
opkssh_enable_home --> off
opkssh_enable_proxy --> off
opkssh_enable_squid --> off
```

**Enable or disable feature**
```
# Enable home-based policy lookup via sudo
sudo setsebool -P opkssh_enable_home on

# Enable proxy support (for dynamic proxy port connections)
sudo setsebool -P opkssh_enable_proxy on

# To turn off a feature
sudo setsebool -P opkssh_enable_proxy off
```
The `-P` flag ensures your setting persist across reboots.

### 4. Configure dynamic proxy ports (optional)

If proxy support is enabled (`opkssh_enable_proxy on`), you can dynamically allow connections to any proxy port by mapping them to the SELinux `http_cache_port_t` type.

**View existing proxy ports**
```bash
semanage port -l | grep http_cache_port_t
```
Example output:
```
http_cache_port_t              tcp      8080, 8118, 8123, 10001-10010
http_cache_port_t              udp      3130
```

**Add a custom proxy port**

If your proxy runs on port `9991/tcp`:
```bash
sudo semanage port -a -t http_cache_port_t -p tcp 9991
```
**Remove a custom proxy port**
```bash
sudo semanage port -d -t http_cache_port_t -p tcp 9991
```
