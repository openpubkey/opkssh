# OPKSSH configuration files

Herein we document the various configuration files used by opkssh.

All our configuration files are space delimited like ssh authorized key files.
We have the follow syntax rules:

- `#` for comments
- `*` for wildcarding a string. This only works for Client-ID. Be very careful with wild carding Client-ID as this can be very dangerous for IDPs other than gitlab-ci and github-actions. This is not currently supported.

Our goal is to have an distinct meaning for each column. This way if we want to extend the ACL rules we can add additional columns.

## Allowed OpenID Providers: `/etc/opk/providers`

This file contains a list of allow OPKSSH OPs (OpenID Providers) and associated Client ID. This file functions as an access control list that enables admins to determine the OpenID Providers and Client IDs they wish to use.

### Columns

- Column 1: Issuer
- Column 2: Client-ID a.k.a. what to match on the audience claim in the ID Token
- Column 3: Expiration policy, options are: `24h`, `48h`, `1week`, `oidc`, `oidc-refreshed`

### Examples

The file lives at `/etc/opk/providers` and the default values are:

```bash
# Issuer Client-ID expiration-policy 
https://accounts.google.com 411517154569-7f10v0ftgp5elms1q8fm7avtp33t7i7n.apps.googleusercontent.com 24h
https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0 096ce0a3-5e72-4da8-9c86-12924b294a01 24h
```

This PR does not support workload OPs like github-actions or gitlab-ci but the intent is for these to use a wildcard `*` for the Client ID (`aud`).

```bash
https://token.actions.githubusercontent.com * oidc
https://gitlab.com OPENPUBKEY-PKTOKEN:* oidc
```

## New authorized identities files: `/etc/opk/auth_id` and `/home/{USER}/.opk/auth_id`

These files are where policies can be configured to determine which identities can assume what linux user accounts.
Linux user accounts are typically referred to in SSH as *principals* and we continue the use of this terminology.

### `/etc/opk/auth_id`

This is a server wide policy file.

```bash
# email/sub principal issuer 
alice alice@example.com https://accounts.google.com
guest alice@example.com https://accounts.google.com 
root alice@example.com https://accounts.google.com 
dev bob@microsoft.com https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0 096ce0a3-5e72-4da8-9c86-12924b294a01
```

`sudo opkssh add {USER} {EMAIL} {ISSUER}`

These `auth_id` files can be edited by hand or you can use the add command to add new policies.
For convenience you can use the shorthand `google` or `azure` rather than specifying the entire issuer.
This is especially useful in the case of azure where the issuer contains a long and hard to remember random string.

It require the following permissions:

```bash
sudo chown root:opksshuser /etc/opk/auth_id
sudo chmod 640 /etc/opk/auth_id
```

`sudo opkssh add root alice@example.com google`

### `/home/{USER}/.opk/auth_id`

This is user/principal specific permissions.
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

## Setup

### Ubuntu

```bash
sudo apt install openssh-server

sudo mkdir -p /etc/opk
sudo touch /etc/opk/auth_id
sudo chown root:opksshuser /etc/opk/auth_id
sudo chmod 640 /etc/opk/auth_id

cd /tmp
git clone https://github.com/openpubkey/opkssh.git
cd openpubkey
sudo go build -v -o /usr/local/bin/opkssh ./opkssh
sudo chmod 711 /usr/local/bin/opkssh
sudo chown root /usr/local/bin/opkssh

sudo touch /etc/opk/providers
sudo chown root:opksshuser /etc/opk/providers
sudo chmod 640 /etc/opk/providers

sudo su
sed -i '/^AuthorizedKeysCommand /s/^/#/' /etc/ssh/sshd_config
sed -i '/^AuthorizedKeysCommandUser /s/^/#/' /etc/ssh/sshd_config
echo "AuthorizedKeysCommand /usr/local/bin/opkssh verify %u %k %t\nAuthorizedKeysCommandUser opksshuser" >> /etc/ssh/sshd_config
sudo systemctl restart ssh

echo "https://accounts.google.com 411517154569-7f10v0ftgp5elms1q8fm7avtp33t7i7n.apps.googleusercontent.com 24h" >> /etc/opk/providers
echo "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0 096ce0a3-5e72-4da8-9c86-12924b294a01 24h" >> /etc/opk/providers
```

Then for each supported user:

```bash
mkdir -p /home/{USER}/.opk
chown {USER}:{USER} /home/{USER}/.opk
chmod 700 /home/e0/.opk

touch /home/{USER}/.opk/auth_id
chown {USER}:{USER} /home/{USER}/.opk/auth_id
chmod 600 /home/{USER}/.opk/auth_id

./opkssh add {EMAIL} {USER} {ISSUER}
```
