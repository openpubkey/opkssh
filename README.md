# opkssh (OpenPubkey SSH)

[![Go Coverage](https://github.com/openpubkey/opkssh/wiki/coverage.svg)](https://raw.githack.com/wiki/openpubkey/opkssh/coverage.html)

**opkssh** is a tool which enables ssh to be used with OpenID Connect allowing SSH access to be managed via identities like `alice@example.com` instead of long-lived SSH keys.
It does not replace SSH, but instead generates SSH public keys containing PK Tokens and configures sshd to verify them. These PK Tokens contain standard [OpenID Connect ID Tokens](https://openid.net/specs/openid-connect-core-1_0.html). This protocol builds on the [OpenPubkey](https://github.com/openpubkey/openpubkey/blob/main/README.md) which adds user public keys to OpenID Connect without breaking compatibility with existing OpenID Provider.

Currently opkssh is compatible with Google, Microsoft/Azure, Gitlab, hello.dev, and Authelia OpenID Providers (OP). See below for the entire list. If you have a gmail, microsoft or a gitlab account you can ssh with that account.

To ssh with opkssh you first need to download the opkssh binary and then run:

```bash
opkssh login
```

This opens a browser window where you can authenticate to your OpenID Provider. This will generate an SSH key in `~/.ssh/id_ecdsa` which contains your OpenID Connect identity.
Then you can ssh under this identity to any ssh server which is configured to use opkssh to authenticate users using their OpenID Connect identities.

```bash
ssh user@example.com
```

### OpenPubkey Mailing List
For updates and announcements join the [OpenPubkey mailing list.](https://groups.google.com/g/openpubkey)

## Getting Started

To ssh with opkssh, Alice first needs to install opkssh using homebrew or manually downloading the binary.

### Homebrew Install (macOS)

To install with homebrew run:

```bash
brew tap openpubkey/opkssh
brew install opkssh
```

### Winget Install (Windows)

To install with winget run:

```powershell
winget install openpubkey.opkssh
```

### Chocolatey Install (Windows)

To install with [Chocolatey](https://chocolatey.org/install) run:

```powershell
choco install opkssh -y
```

### Manual Install (Windows, Linux, macOS)

To install manually, download the opkssh binary and run it:

|           | Download URL |
|-----------|--------------|
|🐧 Linux (x86_64)   | [github.com/openpubkey/opkssh/releases/latest/download/opkssh-linux-amd64](https://github.com/openpubkey/opkssh/releases/latest/download/opkssh-linux-amd64) |
|🐧 Linux (ARM64/aarch64)    | [github.com/openpubkey/opkssh/releases/latest/download/opkssh-linux-arm64](https://github.com/openpubkey/opkssh/releases/latest/download/opkssh-linux-arm64) |
|🍎 macOS (x86_64)             | [github.com/openpubkey/opkssh/releases/latest/download/opkssh-osx-amd64](https://github.com/openpubkey/opkssh/releases/latest/download/opkssh-osx-amd64) |
|🍎 macOS (ARM64/aarch64)             | [github.com/openpubkey/opkssh/releases/latest/download/opkssh-osx-arm64](https://github.com/openpubkey/opkssh/releases/latest/download/opkssh-osx-arm64) |
| ⊞ Win              | [github.com/openpubkey/opkssh/releases/latest/download/opkssh-windows-amd64.exe](https://github.com/openpubkey/opkssh/releases/latest/download/opkssh-windows-amd64.exe) |

To install on Windows run:

```powershell
curl https://github.com/openpubkey/opkssh/releases/latest/download/opkssh-windows-amd64.exe -o opkssh.exe
```

To install on macOS run:

```bash
curl -L https://github.com/openpubkey/opkssh/releases/latest/download/opkssh-osx-amd64 -o opkssh; chmod +x opkssh
```

To install on linux, run:

```bash
curl -L https://github.com/openpubkey/opkssh/releases/latest/download/opkssh-linux-amd64 -o opkssh; chmod +x opkssh
```

or for ARM

```bash
curl -L https://github.com/openpubkey/opkssh/releases/latest/download/opkssh-linux-arm64 -o opkssh; chmod +x opkssh
```

### SSHing with opkssh

After downloading opkssh run:

```cmd
opkssh login
```

This opens a browser window to select which OpenID Provider you want to authenticate against.
After successfully authenticating opkssh generates an SSH public key in `~/.ssh/id_ecdsa` which contains your PK Token.
By default this ssh key expires after 24 hours and you must run `opkssh login` to generate a new ssh key.

Since your PK Token has been saved as an SSH key you can SSH as normal:

```bash
ssh root@example.com
```

This works because SSH sends the public key written by opkssh in `~/.ssh/id_ecdsa` to the server and sshd running on the server will send the public key to the opkssh command to verify. This also works for other protocols that build on ssh like [sftp](https://en.wikipedia.org/wiki/SSH_File_Transfer_Protocol) or ssh tunnels.

```bash
sftp root@example.com
```

### Custom key name

<details>
<summary>Instructions</summary>

#### SSH command

Tell opkssh to store the name the key-pair `opkssh_server_group1`

```cmd
opkssh login -i opkssh_server_group1
```

Tell ssh to use the generated key pair.

```bash
ssh -o "IdentitiesOnly=yes" -i ~/.ssh/opkssh_server_group1 root@example.com
```

We recommend specifying `-o "IdentitiesOnly=yes"` as it tells ssh to only use the provided key. Otherwise ssh will cycle through other keys in `~/.ssh` first and may not get to the specified ones. Servers are configured to only allow 6 attempts by default the config key is `MaxAuthTries 6`.

</details>

### Installing on a Server

To configure a linux server to use opkssh simply run (with root level privileges):

```bash
wget -qO- "https://raw.githubusercontent.com/openpubkey/opkssh/main/scripts/install-linux.sh" | sudo bash
```

This downloads the opkssh binary, installs it as `/usr/local/bin/opkssh`, and then configures ssh to use opkssh as an additional authentication mechanism.

To allow a user, `alice@gmail.com`, to ssh to your server as `root`, run:

```bash
sudo opkssh add root alice@gmail.com google
```

To allow a group, `ssh-users`, to ssh to your server as `root`, run:

```bash
sudo opkssh add root oidc:groups:ssh-users google
```

We can also enforce policy on custom claims.
For instance to require that root access is only granted to users whose ID Token has a claim `https://acme.com/groups` with the value `ssh-users` run:

```bash
sudo opkssh add root oidc:\"https://acme.com/groups\":ssh-users google
```

which will add that line to your OPKSSH policy file.

## How it works

We use two features of SSH to make this work.
First we leverage the fact that SSH public keys can be SSH certificates and SSH Certificates support arbitrary extensions.
This allows us to smuggle your PK Token, which includes your ID Token, into the SSH authentication protocol via an extension field of the SSH certificate.
Second, we use the `AuthorizedKeysCommand` configuration option in `sshd_config` (see [sshd_config manpage](https://man.openbsd.org/sshd_config.5#AuthorizedKeysCommand)) so that the SSH server will send the SSH certificate to an installed program that knows how to verify PK Tokens.

## What is supported

### Client support

| OS        | Supported | Tested  | Version Tested          |
| --------- | --------  | ------- | ----------------------- |
| Linux     | ✅        | ✅      |  Ubuntu 24.04.1 LTS     |
| macOS     | ✅        | ✅      |  macOS 15.3.2 (Sequoia) |
| Windows11 | ✅        | ✅      |  Windows 11             |

### Server support

| OS               | Supported | Tested | Version Tested         | Possible Future Support |
| ---------------- | --------  | ------ | ---------------------- | ----------------------- |
| Linux            | ✅        | ✅     |  Ubuntu 24.04.1 LTS    | -                       |
| Linux            | ✅        | ✅     |  Centos 9              | -                       |
| Linux            | ✅        | ✅     |  Arch Linux            | -                       |
| Linux            | ✅        | ✅     |  openSUSE Tumbleweed   | -                       |
| macOS            | ❌        | ❌     |  -                     | Likely                  |
| Windows11        | ❌        | ❌     |  -                     | Likely                  |

## Server Configuration

All opkssh configuration files are space delimited and live on the server.
Below we discuss our basic policy system, to read how to configure complex policies rules see our [documentation on our policy plugin system](docs/policyplugins.md). Using the policy plugin system you can enforce any policy rule that be computed on a [Turing Machine](https://en.wikipedia.org/wiki/Turing_machine).

### `/etc/opk/providers`

`/etc/opk/providers` contains a list of allowed OPs (OpenID Providers), a.k.a. IDPs.
This file functions as an access control list that enables admins to determine the OpenID Providers and Client IDs they wish to rely on.

- Column 1: Issuer URI of the OP
- Column 2: Client-ID, the audience claim in the ID Token
- Column 3: Expiration policy, options are:
  - `12h` - user's ssh public key expires after 12 hours,
  - `24h` - user's ssh public key expires after 24 hours,
  - `48h` - user's ssh public key expires after 48 hours,
  - `1week` - user's ssh public key expires after 1 week,
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
  - Group - the name of the group that the user is part of. This uses the `groups` claim which is presumed to
    be an array. The group identifier uses a structured identifier. I.e. `oidc:groups:{groupId}`. Replace the `groupId`
    with the id of your group. If your group contains a colon, escape it `oidc:"https://acme.com/groups":{groupId}`.
- Column 3: Issuer URI

```bash
# email/sub principal issuer
alice alice@example.com https://accounts.google.com
guest alice@example.com https://accounts.google.com
root alice@example.com https://accounts.google.com
dev bob@microsoft.com https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0

# Group identifier
dev oidc:groups:developer https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0
dev oidc:"https://acme.com/groups":developer https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0
```

To add new rule run:

`sudo opkssh add <user> <email/sub/group> <issuer>`

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

# Group identifier
dev oidc:groups:developer https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0
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

## Custom OpenID Providers (Authentik, Authelia, Keycloak, Zitadel...)

To log in using a custom OpenID Provider, run:

```bash
opkssh login --provider="<issuer>,<client_id>"
```

or in the rare case that a client secret is required by the OpenID Provider:

```bash
opkssh login --provider="<issuer>,<client_id>,<client_secret>,<scopes>"
```

where issuer, client_id and client_secret correspond to the issuer client ID and client secret of the custom OpenID Provider.

For example if the issuer is `https://authentik.local/application/o/opkssh/` and the client ID was `ClientID123`:

```bash
opkssh login --provider="https://authentik.local/application/o/opkssh/,ClientID123"
```

to specify scopes

```bash
opkssh login --provider="https://authentik.local/application/o/opkssh/,ClientID123,,openid profile email groups"
```

You can use this shortcut which will use a provider alias to find the provider.

```bash
opkssh login authentik
```

This alias to provider mapping be can configured using the OPKSSH_PROVIDERS environment variables.

### Client Config File

Rather than type in the provider each time, you can create a client config file by running `opkssh login --create-config` at
`C:\Users\{USER}\.opk\config.yml` on windows and `~/.opk/config.yml` on linux.
You can then edit this config file to add your provider.

<details>
<summary>config.yml</summary>

You can delete any providers you don't plan on using.
If you have a provider you want to open by default, change `default_provider` to the name of your alias of your custom provider.

```yaml
---
default_provider: webchooser

providers:
  - alias: google
    issuer: https://accounts.google.com
    client_id: 206584157355-7cbe4s640tvm7naoludob4ut1emii7sf.apps.googleusercontent.com
    client_secret: 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
    scopes: openid email profile
    access_type: offline
    prompt: consent
    redirect_uris:
      - http://localhost:3000/login-callback
      - http://localhost:10001/login-callback
      - http://localhost:11110/login-callback

  - alias: azure microsoft
    issuer: https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0
    client_id: 096ce0a3-5e72-4da8-9c86-12924b294a01
    scopes: openid profile email offline_access
    access_type: offline
    prompt: consent
    redirect_uris:
      - http://localhost:3000/login-callback
      - http://localhost:10001/login-callback
      - http://localhost:11110/login-callback

  - alias: gitlab
    issuer: https://gitlab.com
    client_id: 8d8b7024572c7fd501f64374dec6bba37096783dfcd792b3988104be08cb6923
    scopes: openid email
    access_type: offline
    prompt: consent
    redirect_uris:
      - http://localhost:3000/login-callback
      - http://localhost:10001/login-callback
      - http://localhost:11110/login-callback

  - alias: hello
    issuer: https://issuer.hello.coop
    client_id: app_xejobTKEsDNSRd5vofKB2iay_2rN
    scopes: openid email
    access_type: offline
    prompt: consent
    redirect_uris:
      - http://localhost:3000/login-callback
      - http://localhost:10001/login-callback
      - http://localhost:11110/login-callback
```

</details>

### Environment Variables

Instead of using the `opkssh login --provider` flag you can also configure the providers to use with environment variables.

The OPKSSH_PROVIDERS variable follow the standard format with `;` delimiting each provider and `,` delimiting fields with a provider for instance:
`{alias},{issuer},{client_id},{client_secret},{scope};{alias},{issuer},{client_id},{client_secret},{scope}...`

You can set them in your [`.bashrc` file](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html) so you don't have to type custom settings each time you run `opk login`.

```bash
export OPKSSH_DEFAULT=WEBCHOOSER
export OPKSSH_PROVIDERS=google,https://accounts.google.com,206584157355-7cbe4s640tvm7naoludob4ut1emii7sf.apps.googleusercontent.com,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;microsoft,https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0,096ce0a3-5e72-4da8-9c86-12924b294a01;gitlab,https://gitlab.com,8d8b7024572c7fd501f64374dec6bba37096783dfcd792b3988104be08cb6923
export OPKSSH_PROVIDERS=$OPKSSH_PROVIDERS;authentik,https://authentik.io/application/o/opkssh/,client_id,,openid profile email
```

The OPKSSH_DEFAULT can be set to one of the provider's alias to set the default provider to use when running `opkssh login`.
WEBCHOOSER will open a browser window to select the provider.

### Redirect URIs

Currently opkssh supports the following redirect URIs. Make sure that the correct redirectURIs have been added at your OpenID Provider:

```
http://localhost:3000/login-callback
http://localhost:10001/login-callback
http://localhost:11110/login-callback
```

### Security Note: Create a new Client ID for opkssh

Do not reuse a client ID between opkssh and other OpenID Connect services.
If the same client ID is used for opkssh as another OpenID Connect authentication service, then an SSH server could replay the ID Token sent in an opkssh SSH key to authenticate to that service.
Such replay attacks can be ruled out by simply using a new client ID with opkssh.

Note that this requirement of using different client IDs for different audiences and uses is not unique to opkssh and is a best practice in OpenID Connect.

### Provider Server Configuration

In the `/etc/opk/providers` file, add the OpenID Provider as you would any OpenID Provider. For example:

```bash
https://authentik.local/application/o/opkssh/ ClientID123 24h
```

Then add identities to the policy to allow those identities SSH to the server:

```bash
opkssh add root alice@example.com https://authentik.local/application/o/opkssh/
```

### Tested

| OpenID Provider                           | Tested | Notes                                                                                                       |
|-------------------------------------------|--------|-------------------------------------------------------------------------------------------------------------|
| [Authelia](https://www.authelia.com/)     | ✅      | [Authelia Integration Guide](https://www.authelia.com/integration/openid-connect/opkssh/)                   |
| [Authentik](https://goauthentik.io/)      | ✅      | Do not add a certificate in the encryption section of the provider                                          |
| [Azure](https://www.azure.com/)           | ✅      | [Entra ID (Azure) Integration Guide](docs/providers/azure.md)
| [Gitlab Self-hosted](https://gitlab.com/) | ✅      | [Configuration guide](docs/gitlab-selfhosted.md)                                                            |
| [Kanidm](https://kanidm.com/)             | ✅      | [Kanidm Integration Guide](https://kanidm.github.io/kanidm/master/integrations/oauth2/examples.html#opkssh) |
| [PocketID](https://pocket-id.org/)        | ✅      | Create a new OIDC Client and inside the new client, check "Public client" on OIDC Client Settings           |
| [Zitadel](https://zitadel.com/)           | ✅      | Check the UserInfo box on the Token Settings                                                                |

Do not use Confidential/Secret mode **only** client ID is needed.

## Developing

For a complete developers guide see [CONTRIBUTING.md](CONTRIBUTING.md)

### Building

Run:

```bash
CGO_ENABLED=false go build -v -o opkssh
chmod u+x opkssh
```

to build with docker run:

```bash
./hack/build.sh
```

### Testing

For unit tests run

```bash
go test ./...
```

For integration tests run:

```bash
./hack/integration-tests.sh
```

## More information

### Documentation
- [docs/config.md](docs/config.md) Documentation of opkssh configuration files.
- [docs/policyplugins.md](docs/policyplugins.md) Documentation of opkssh policy plugins and how to use them to implement complex policies.
- [scripts/installing.md](scripts/installing.md) Documentation of the server install script that opkssh uses to configure an SSH server to accept opkssh SSH certificates. Explains how to manually install opkssh on a server.

### Guides
- [CONTRIBUTING.md](https://github.com/openpubkey/opkssh/blob/main/CONTRIBUTING.md) Guide to contributing to opkssh (includes developer help).
- [docs/gitlab-selfhosted.md](docs/gitlab-selfhosted.md) Guide on configuring and using a self hosted GitLab instance with opkssh.
- [docs/paramiko.md](docs/paramiko.md) Guide to using the python SSH paramiko library with opkssh.
- [docs/putty.md](docs/putty.md) Guide to using PuTTY with opkssh.