
# Installing opkssh

This document provides a detailed description of how our [install-linux.sh](https://raw.githubusercontent.com/openpubkey/opkssh/main/scripts/install-linux.sh) script works and the security protections used.

If you just want to install opkssh you should run:

```bash
wget -qO- "https://raw.githubusercontent.com/openpubkey/opkssh/main/scripts/install-linux.sh" | sudo bash
```

## Script commands

Running `./install-linux.sh --help` will show you all available flags.

`--nosshd-restart` turns off the sshd restart. This is useful in some docker setups where restarting sshd can break docker.

`--install-from=FILEPATH` allows you to install the opkssh binary from a local file.
This is useful if you want to install a locally built opkssh binary.

`--install-version=VER` downloads and installs a particular release of opkssh. By default we download and install the latest release of opkssh.

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

**4: Configure sshd to use opkssh.** Add the following lines to the sshd configuration file `/etc/ssh/sshd_config`.

```bash
AuthorizedKeysCommand /usr/local/bin/opkssh verify %u %k %t
AuthorizedKeysCommandUser opksshuser
```

Then create the required AuthorizedKeysCommandUser and group

```bash
sudo groupadd --system opksshuser
sudo useradd -r -M -s /sbin/nologin -g opksshuser opksshuser
```

**5: Restart sshd.**

Configures a sudoer command so that the opkssh AuthorizedKeysCommand process can call out to the shell to run `opkssh readhome <username>` and thereby read the policy file for the user in `/home/<username>/.opk/auth_id`.

```bash
"opksshuser ALL=(ALL) NOPASSWD: /usr/local/bin/opkssh readhome *"
```

This config lives in `/etc/sudoers.d/opkssh` and must have the permissions `440` with root being the owner.

**6: Restart sshd.**

```bash
sudo systemctl restart sshd
```
