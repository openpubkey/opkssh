# opkssh configuration files

Herein we document the various configuration files used by opkssh.
The documentation for the `/etc/opk/policy.d/` policy plugin system is found [here](policyplugins.md).

All our configuration files are space delimited like ssh authorized key files.
We have the follow syntax rules:

- `#` for comments

Our goal is to have an distinct meaning for each column. This way if we want to extend the rules we can add additional columns.

## Allowed OpenID Providers: `/etc/opk/providers`

This file functions as an access control list that enables admins to determine the OpenID Providers and Client IDs they wish to use.
This file contains a list of allowed OPKSSH OPs (OpenID Providers) and the associated client ID.
The client ID must match the aud (audience) claim in the PK Token. 

### Columns

- Column 1: Issuer
- Column 2: Client-ID a.k.a. what to match on the aud claim in the ID Token
- Column 3: Expiration policy, options are: `24h`, `48h`, `1week`, `oidc`, `oidc-refreshed`

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
```

These `auth_id` files can be edited by hand or you can use the add command to add new policies. The add command has the following syntax.

`sudo opkssh add {USER} {EMAIL|SUB|GROUP} {ISSUER}`

For convenience you can use the shorthand `google`, `azure`, `gitlab` rather than specifying the entire issuer.
This is especially useful in the case of azure where the issuer contains a long and hard to remember random string.

The following command will allow `alice@example.com` to ssh in as `root`.

Groups must be prefixed with `oidc:group`. So to allow anyone with the group `admin` to ssh in as root you would run the command:

```bash
sudo opkssh add root oidc:group:admin azure
```

Note that currently Google does not put their groups in the ID Token, so groups based auth does not work if you OpenID Provider is Google. 

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




