# opkssh configuration files

Herein we document the various configuration files used by opkssh.
The documentation for the `/etc/opk/policy.d/` policy plugin system is found [here](policyplugins.md).

All our configuration files are space delimited like ssh authorized key files.
We have the follow syntax rules:

- `#` for comments

Our goal is to have an distinct meaning for each column. This way if we want to extend the rules we can add additional columns.

## Client config `~/.opk/config.yml`

The config file for the client is saved in `~/.opk/config.yml`.
It configures which OpenID Providers the user can log in with.
This file is not required to exist to use opkssh and it is not created by default.
To create it, simple run `~/opkssh login --create-config`.

The default client config can be found in [../commands/config/default-client-config.yml](../commands/config/default-client-config.yml).

The client config can be used to configure the following values:

- **default_provider** By default this is set to the webchooser, which opens a webpage and allows the user to select the OpenID Provider they want by clicking. However if you wish to always connect to one particular OpenID Provider you can set this to the alias of that OpenID Provider and it will skip the web chooser and automatically just open a browser window to that provider.

- **providers** This allows you to configure all the OpenID Providers you wish to use. See example below.
  - **send_access_token** Is a boolean value scoped to a particular provider. It determines if opkssh should put the user's access token into the SSH public key (SSH Certificate). This is useful for allowing the opkssh verifier to read claims not available in the ID Token that can only be read from the OpenID Provider's [userinfo endpoint](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo). The opkssh verifier on the SSH server will use the access token to make a call to the OpenID Provider's userinfo endpoint. Configuration option false by default as SSH will send SSH Public Keys to any host you are attempting to SSH into. Before setting this to true carefully consider the security implications of including the access token in the SSH Public key.

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
    send_access_token: false

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


```

## Server config `/etc/opk/config.yml`

This is the config file for opkssh when used on the SSH server.
It supports setting additional environment variables when `opkssh verify` is called.
For instance if you want to specify the URI of a proxy server you can pass the environment variable HTTPS_PROXY:

```yml
---
env_vars:
  HTTPS_PROXY: http://yourproxy:3128
```

It also supports a `deny_emails` field. This field is a YAML array of strings, where each string is an email address opkssh should never allow. An ID Token has a claim for an email on this list it will reject it.

```yml
---
deny_emails:
  - "user1@example.com"
  - "user2@example.com"
```

- When a user attempts to authenticate, OPKSSH checks if their email is present in the `deny_emails` list.
- If a match is found (case-insensitive), authentication is denied, regardless of other authorization policies.

It also supports a `deny_users` field. This field is a YAML array of strings, where each string is a user (linux principal) that opkssh never allow. This is equivalent to the `DenyUsers` field in [sshd_config](https://man.openbsd.org/sshd_config).

Both `deny_emails` and `deny_users` are evaluated before policy.

### Server config permissions

The server config file requires the following permissions be set:

```bash
sudo chown root:opksshuser /etc/opk/config.yml
sudo chmod 640 /etc/opk/config.yml
```

## Allowed OpenID Providers: `/etc/opk/providers`

This file functions as an access control list that enables admins to determine the OpenID Providers and Client IDs they wish to use.
This file contains a list of allowed OPKSSH OPs (OpenID Providers) and the associated client ID.
The client ID must match the aud (audience) claim in the PK Token.

### Columns

- Column 1: Issuer
- Column 2: Client-ID a.k.a. what to match on the aud claim in the ID Token
- Column 3: Expiration policy, options are: `12h`, `24h`, `48h`, `1week`, `oidc`, `oidc-refreshed`

### Examples

The file lives at `/etc/opk/providers`. The default values are:

```bash
# Issuer Client-ID expiration-policy 
https://accounts.google.com 206584157355-7cbe4s640tvm7naoludob4ut1emii7sf.apps.googleusercontent.com 24h
https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0 096ce0a3-5e72-4da8-9c86-12924b294a01 24h
https://gitlab.com 8d8b7024572c7fd501f64374dec6bba37096783dfcd792b3988104be08cb6923 24h
```

## Authorized identities files: `/etc/opk/auth_id` and `/home/{USER}/.opk/auth_id`

These files contain the policies to determine which identities can assume what linux user accounts.
Linux user accounts are typically referred to in SSH as *principals* and we use this terminology.

We support matching on email, sub (subscriber) or group.

We support email "wildcard" validation using the `oidc-match-end:email:` prefix. This allows administrators to match user emails by domain or other patterns at the end of the email string.

- This matching is **case-insensitive**.
- Use with care, as allowing a domain grants access to all users at that domain.

### System authorized identity file `/etc/opk/auth_id`

This is a server wide policy file.

```bash
# email/sub principal issuer 
alice alice@example.com https://accounts.google.com
guest alice@example.com https://accounts.google.com 
root alice@example.com https://accounts.google.com 
dev bob@microsoft.com https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0

# Group identifier 
dev oidc:groups:developer https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0

# Email suffix wildcard matching all emails ending in `@example.com`
dev oidc-match-end:email:@example.com https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0
```

These `auth_id` files can be edited by hand or you can use the add command to add new policies. The add command has the following syntax.

`sudo opkssh add <user> <email|sub|claim> <issuer>`

For convenience you can use the shorthand `google`, `azure`, `gitlab` rather than specifying the entire issuer.
This is especially useful in the case of azure where the issuer contains a long and hard to remember random string.

The following command will allow `alice@example.com` to ssh in as `root`.

Claims must be prefixed with `oidc:{CLAIM}` e.g. for the group claim `oidc:group`. To allow anyone with the group `admin` to ssh in as root you would run the command:

```bash
sudo opkssh add root oidc:group:admin azure
```

Note that currently Google does not put their groups in the ID Token, so groups based auth does not work if you OpenID Provider is Google.

We support policy on claims that are also URIs as this is a common pattern for groups in some systems. 
To require that root access is only granted to users whose ID Token has a claim `https://acme.com/groups` with the value `ssh-users` run:

```bash
sudo opkssh add root oidc:\"https://acme.com/groups\":ssh-users google
```

which will add that line to your OPKSSH policy file.

The system authorized identity file requires the following permissions:

```bash
sudo chown root:opksshuser /etc/opk/auth_id
sudo chmod 640 /etc/opk/auth_id
```

**Note:** The permissions for the system authorized identity file are different than the home authorized identity file.

### Home authorized identity file `/home/{USER}/.opk/auth_id`

This is user/principal specific permissions.
That is, if it is in `/home/alice/.opk/auth_id` it can only specify who can assume the principal `alice` on the server.

```bash
# email/sub principal issuer 
alice alice@example.com https://accounts.google.com

# Group identifier 
alice oidc:groups:developer https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0
```

Home authorized identity file requires the following permissions:

```bash
chown {USER}:{USER} /home/{USER}/.opk/auth_id
chmod 600 /home/{USER}/.opk/auth_id
```

## See Also

Our documentation on the changes our install script makes to a server: [installing.md](../scripts/installing.md)
