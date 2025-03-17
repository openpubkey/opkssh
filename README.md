# OpenPubkey SSH (OPKSSH)

[![Go Coverage](https://github.com/openpubkey/opkssh/wiki/coverage.svg)](https://raw.githack.com/wiki/openpubkey/opkssh/coverage.html)

opkssh is a tool which enables OpenID Connect to be used with ssh.
It does not replace ssh, but rather generates ssh public keys that contain PK Tokens and configures sshd to verify the PK Token in the ssh public keys.
PK Tokens are a backwards compatible extension of ID Tokens which contain a public key.
For more details on PK Tokens see [OpenPubkey](https://github.com/openpubkey/openpubkey/blob/main/README.md)

Currently opkssh supports Google, Microsoft/Azure and Gitlab. If you have a gmail, microsoft or a gitlab account you can ssh with that account.

## Getting Started

To ssh with opkssh, Alice first needs to install opkssh using homebrew or manually downloading the binary.

To install with homebrew run:

```bash
brew tap openpubkey/opkssh
brew install opkssh
```

To install manually, you can download the opkssh binary and run it:

```bash
curl -L https://github.com/openpubkey/opkssh/releases/latest/download/opkssh-osx-amd64 -o opkssh; chmod +x opkssh
```

|           | Download URL |
|-----------|--------------|
|🐧 Linux   | [github.com/openpubkey/opkssh/releases/latest/download/opkssh-linux-amd64](https://github.com/openpubkey/opkssh/releases/latest/download/opkssh-linux-amd64) |
|🍎 OSX   | [github.com/openpubkey/opkssh/releases/latest/download/opkssh-osx-amd64](https://github.com/openpubkey/opkssh/releases/latest/download/opkssh-osx-amd64) |
| ⊞ Win   | [github.com/openpubkey/opkssh/releases/latest/download/opkssh-windows-amd64.exe](https://github.com/openpubkey/opkssh/releases/latest/download/opkssh-windows-amd64.exe) |


Once Alice downloads opkssh on her local computer, she Alice runs:

```bash
opkssh login
```

which opens a browser window to authenticate to google and then generates an SSH public key in `~/.ssh/id_ecdsas` which contains her PK Token.
By default this key will expire after 24 hours and Alice must run `opkssh login` to generate a new ssh key.

Since her PK Token has been saved as an SSH key she can SSH as normal:

```bash
ssh root@server.example.com
```

This works because SSH will send the public key opkssh wrote in `~/.ssh/id_dsaKey` to the server and sshd running on the server will send the public key to opkssh to verify.

### Installing on a server

To configure a linux server to use opkssh simply run (with root level privileges):

```bash
wget -qO- "https://raw.githubusercontent.com/openpubkey/opkssh/main/scripts/install-linux.sh" | sudo bash
```

 This will download the opkssh binary, install it as `/usr/local/bin/opkssh`, and then configure ssh to use opkssh as an additional authentication mechanism.

To allow a user, `alice@gmail.com`, to ssh to your server as `root`, run:

```bash
sudo opkssh add root alice@gmail.com google
```

## How it works

We use two features of SSH to make this work.
First we leverage the fact that SSH public keys can be SSH certificates and SSH Certificates support arbitrary extensions.
This allows us to smuggle your PK Token, which includes your ID Token, into the SSH authentication protocol via an extension field of the SSH certificate.
Second, we use the `AuthorizedKeysCommand` configuration option in `sshd_config` (see [sshd_config manpage](https://man.openbsd.org/sshd_config.5#AuthorizedKeysCommand)) so that the SSH server will send the SSH certificate to an installed program that knows how to verify PK Tokens.


## What is supported

### Client support

| OS               | Supported | Tested | Version Tested         | Possible Future Support |
| --------        | --------      | ------- | ---------------------- |----------- |
| Linux       | ✅             |  ✅     |  Ubuntu 24.04.1 LTS  | -  |
| OSX       | ✅             |  ✅     |  -  | -  |
| Windows11 | ✅            |   ✅     |  -  | -  |

### Server support

| OS               | Supported | Tested | Version Tested         | Possible Future Support |
| --------        | --------      | ------- | ---------------------- |----------- |
| Linux       | ✅             |  ✅     |  Ubuntu 24.04.1 LTS  | -  |
| OSX       | ❌             |  ❌     |  -  | Likely  |
| Windows11 | ❌            |   ❌     |  -                              | Likely |

## Configuration

All opkssh configuration files are space delimited and live on the server.
We currently have no configuration files on the client.

### `/etc/opk/providers`

`/etc/opk/providers` contains a list of allowed OPs (OpenID Providers), a.k.a. IDPs.
This file functions as an access control list that enables admins to determine the OpenID Providers and Client IDs they wish to rely on.

- Column 1: Issuer URI of the OP
- Column 2: Client-ID, the audience claim in the ID Token
- Column 3: Expiration policy, options are:
  - `24h` - user's ssh public key expires after 24 hours,
  - `48h` - user's ssh public key expires after 24 hours,
  - `1week` - user's ssh public key expires after 24 hours,
  - `oidc` - user's ssh public key expires when the ID Token expires
  - `oidc-refreshed` - user's ssh public key expires when their refreshed ID Token expires.

By default we use `24h` as it requires that the user authenticate to their OP once a day. Most OPs expire ID Tokens every one to two hours, so if `oidc` the user will have to sign multiple times a day. `oidc-refreshed` is supported but complex and not currently recommended unless you know what you are doing.

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

## `/etc/opk/auth_id`

`/etc/opk/auth_id` is the global authorized identities file.
This is a server wide file where policies can be configured to determine which identities can assume what linux user accounts.
Linux user accounts are typically referred to in SSH as *principals* and we continue the use of this terminology.

- Column 1: The principal, i.e., the account the user wants to assume
- Column 2: Email address or subject ID of the user (choose one)
  - Email - the email of the identity
  - Subject ID - an unique ID for the user set by the OP. This is the `sub` claim in the ID Token.
- Column 3: Issuer URI

```bash
# email/sub principal issuer 
alice alice@example.com https://accounts.google.com
guest alice@example.com https://accounts.google.com 
root alice@example.com https://accounts.google.com 
dev bob@microsoft.com https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0
```

To add new rule run:

`sudo opkssh add {USER} {EMAIL} {ISSUER}`

These `auth_id` files can be edited by hand or you can use the add command to add new policies.
For convenience you can use the shorthand `google` or `azure` rather than specifying the entire issuer.
This is especially useful in the case of azure where the issuer contains a long and hard to remember random string. For instance:

`sudo opkssh add dev bob@microsoft.com azure`

`/etc/opk/auth_id` requires the following permissions (by default we create all configuration files with the correct permissions):

```bash
sudo chown root:opksshuser /etc/opk/auth_id
sudo chmod 640 /etc/opk/auth_id
```

### `~/.opk/auth_id`

This is a local version of the auth_id file.
It lives in the user's home directory (`/home/{USER}/.opk/auth_id`) and allows users to add or remove authorized identities without requiring root level permissions.

It can only be used for user/principal whose home directory it lives in.
That is, if it is in `/home/alice/.opk/auth_id` it can only specify who can assume the principal `alice` on the server.

```bash
# email/sub principal issuer 
alice alice@example.com https://accounts.google.com
```

It requires the following permissions:

```bash
chown {USER}:{USER} /home/{USER}/.opk/auth_id
chmod 600 /home/{USER}/.opk/auth_id
```

### AuthorizedKeysCommandUser

We use a low privilege user for the SSH AuthorizedKeysCommandUser.
Our install script creates this user and group automatically by running:

```bash
sudo groupadd --system opksshuser
sudo useradd -r -M -s /sbin/nologin -g opksshuser opksshuser
```

We then add the following lines to `/etc/ssh/sshd_config`

```bash
AuthorizedKeysCommand /usr/local/bin/opkssh verify %u %k %t
AuthorizedKeysCommandUser opksshuser
```

## More information

We document how to manually install opkssh on a server [here](https://raw.githubusercontent.com/openpubkey/opkssh/main/opkssh/scripts/installing.md).
