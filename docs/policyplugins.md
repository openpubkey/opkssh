# Policy plugins

Inspired by the power of [the OpenSSH AuthorizedKeysCommand](https://man.openbsd.org/sshd_config.5#AuthorizedKeysCommand), opkssh provides policy plugins.
These policy plugins provide a simple way to bring your own policy which replaces the default opkssh policy by placing a configuration file in `/etc/opk/policy.d`.

This calls out to a command to evaluate policy. If the command returns anything else other than "allowed" and exit code 0, the call is viewed as a policy rejection.

The policy plugin does not bypass the providers check. This means that a policy plugin can count on the ID Token having been validated as validly signed by one of the OPs in the /etc/opk/providers. We do this to allow people to write policies without having to rebuild all the code in opkssh verify.

For example by creating the file in `/etc/opk/policy.d/example-plugin.yml`:

```yml
name: Example plugin config
command: /etc/opk/plugin-cmd.sh %{u} %{email} %{email_verified}
```

and then when someone runs `ssh dev alice@example.com` the opkssh will call `/tmp/plugin-cmd.sh dev alice@gmail.com true` to determine if policy should allow `alice@gmail.com` to assume ssh access as the linux principal `dev`.

The command `/etc/opk/plugin-cmd.sh` would allow `alice@example.com` to log as any user:

```bash
#!/usr/bin/env sh

principal="$1"
email="$2"
email_verified="$3"

if [ "$email" = "alice@example.com" ] && [ "$email_verified" = "true" ]; then
    echo "allow"
    exit 0
else 
    echo "deny"
    exit 1
fi
```

## Permission requirements

The policy plugin config file must have the permission `640` with ownership set to `root:opksshuser`.

```bash
chmod 640 /etc/opk/policy.d/example-plugin.yml
chmod root:opksshuser /etc/opk/policy.d/example-plugin.yml
```

The policy plugin command file must have the permission `755` or `555` with ownership set to `root:opksshuser`.

```bash
chmod 755 /etc/opk/plugin-cmd.sh
chmod root:opksshuser /etc/opk/plugin-cmd.sh
```

These rules are required so that these policy files are only write by root.

## Tokens

We support the following tokens to send information about the login attempt to the policy plugin command

### OpenSSH Tokens

We inherit the following tokens from OpenSSHd

- %{u} Target username (requested principal)
- %{k} Base64-encoded SSH public key (SSH certificate) provided for authentication. This is useful if someone really wants to see everything opkssh sees.
- %{t} Public key type (SSH certificate format, e.g., [ecdsa-sha2-nistp256-cert-v01@openssh.com](mailto:ecdsa-sha2-nistp256-cert-v01@openssh.com))

### Tokens for ID Token claims

- %{iss} Issuer (iss) claim
- %{sub} Sub claim of the identity
- %{email} Email claim of the identity
- %{email_verified} Optional claim that signals if the email address has been verified
- %{aud} Audience/client_id (aud) claim
- %{exp} Expiration (exp) claim
- %{nbf} Not Before (nbf) claim
- %{iat} IssuedAt
- %{jti} JTI JWT ID

#### Misc

- %{payload} Based64-encoded ID Token payload (JSON)
- %{upk} Base64-encoded JWK of the user's public key in the PK Token
- %{idt} Compact-encoded ID Token
- %{pkt} Compact-encoded PK Token
- %{config} Base64 encoded bytes of the plugin config used in this call. Useful for debugging.
- %{groups} Groups claim (if present) of the identity.

### Handling missing or empty claims

Note that if an claim is not present we set to the empty string, "". For instance for an ID Token payload with `aud` we set to the empty string ("") and no email claim:

```json
{
"iss":"https://example.com",
"sub":"123",
"aud":"",
"exp":34,
"iat":12,
"email":"alice@example.com",
}
```

with following plugin_config that requires `email` and `aud`:

```yml
name: example command
command: /etc/opk/plugin-cmd.sh %{iss} %sub} %{email} %{exp} %{aud}
```

would result in a command string such as: `{"/etc/opk/plugin-cmd.sh", "https://example.com", "123", "", "34", ""}`

We do this to avoid situations where a policy plugin includes a claim to check if present but does not require it. If we threw an error if it was not found then this may cause hard to debug policy failures when an ID Token is missing that claim.

If a policy plugin wishes to discriminate between claims which are missing or merely set to the empty string, they could use the `%idt` and parse the ID Token themselves.

## Example policy configs

### Match username to email address

This policy plugin allows ssh access as the principal (linux user) if the principal is the same as the username part of the email address in the ID Token, i.e. when email of the user fits the pattern `principal@example.com`.  For instance this would allow `ssh alice@hostname` if Alice's email address is `alice@example.com`.

To prevent issues where someone might get the email `root@example.com` it has a list of default linux principles always denies such as `root`, `admin`, `email`, `backup`...

The last part of the email address must match the value supplied at the commandline, for instance in the policy plugin config below, this would be `example.com`. If you wanted to use this for say `gmail.com` change this value from `example.com` to `gmail.com` in the config:


```yml
name: Match linux username to email username
command: /etc/opk/match-email.sh %{u} %{email} %{email_verified} example.com
```

```bash
#!/usr/bin/env sh

principal="$1"
email="$2"
email_verified="$3"
req_domain="$4"

DENY_LIST="root admin email backup"

for deny_principal in $DENY_LIST; do
  if [ "$principal" = "$deny_principal" ]; then
    echo "deny"
    exit 1
  fi
done

expectedEmail="${principal}@${req_domain}"
if [ "$expectedEmail" = "$email" ] && [ "$email_verified" = "true" ]; then
  echo "allow"
  exit 0
else
  echo "deny"
  exit 1
fi
```
