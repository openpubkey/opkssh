# Policy plugins

Inspired by the power of [the OpenSSH AuthorizedKeysCommand](https://man.openbsd.org/sshd_config.5#AuthorizedKeysCommand), opkssh provides policy plugins.
These policy plugins provide a simple way to bring your own policy which extends the default opkssh policy.

To use your own policy create a policy plugin config file in `/etc/opk/policy.d`. This config files specifies what command you want to calls out to evaluate policy. If the command returns anything else other than "allowed" and exit code 0, this is viewed as a policy rejection.

The policy plugin does not bypass the providers check. This means that a policy plugin can count on the ID Token having been validated as validly signed by one of the OPs in the `/etc/opk/providers`. We do this to allow people to write policies without having to rebuild all the code in opkssh verify.

For example by creating the file in `/etc/opk/policy.d/example-plugin.yml`:

```yml
name: Example plugin config
command: /etc/opk/plugin-cmd.sh
```

and then when someone runs `ssh dev alice@example.com` the opkssh will call `/tmp/plugin-cmd.sh` to determine if policy should allow `alice@gmail.com` to assume ssh access as the linux principal `dev`. [Environment variables](https://en.wikipedia.org/wiki/Environment_variable) are set to communicate the details of the ssh login attempt to the command such as:

```bash
OPKSSH_PLUGIN_U=dev
OPKSSH_PLUGIN_EMAIL=alice@gmail.com
OPKSSH_PLUGIN_EMAIL_VERIFIED=true
```

The command `/etc/opk/plugin-cmd.sh` would allow `alice@example.com` to log as any user:

```bash
#!/usr/bin/env sh

if [ "${OPKSSH_PLUGIN_EMAIL}" = "alice@example.com" ] && [ "${OPKSSH_PLUGIN_EMAIL_VERIFIED}" = "true" ]; then
    echo "allow"
    exit 0
else
    echo "deny"
    exit 1
fi
```

**Important:** If you have multiple policy plugins only one of them needs to return "allow" for the action to be allowed.
If you added five policy plugins and four them say "deny" and one of them says "allow" the allow wins out. Additionally policy plugins do not disable standard policy.
To completely turn off standard policy and only use policy plugins ensure all auth_id files are empty.

The pseudocode policy is:

1. pluginAllowsAccess = false
2. FOR each policy-plugin config in `/etc/opk/policy.d/*.yml`
   1. IF config.command() == "allow":
       1. pluginAllowsAccess = true
3. IF pluginAllowsAccess == true:
   1. return "allow"
4. ELSE IF standardPolicy() == "allow"
   1. return "allow"
5. ELSE:
   1. return "deny"

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

## Environment Variables Set

We support set the following information about the login attempt to the policy plugin command

### OpenSSH

We provide the following values specified by [OpenSSHd AuthorizedKeysCommand TOKENS pattern](https://man.openbsd.org/sshd_config#TOKENS).

- OPKSSH_PLUGIN_U Target username (requested principal). This is `%u` token in SSH.
- OPKSSH_PLUGIN_K Base64-encoded SSH public key (SSH certificate) provided for authentication. This is useful if someone really wants to see everything opkssh sees. This is the `%k` token in SSH.
- OPKSSH_PLUGIN_T Public key type (SSH certificate format, e.g., [ecdsa-sha2-nistp256-cert-v01@openssh.com](mailto:ecdsa-sha2-nistp256-cert-v01@openssh.com)). This is the `%t` token in SSH.

### From ID Token claims

- OPKSSH_PLUGIN_ISS Issuer (iss) claim
- OPKSSH_PLUGIN_SUB Sub claim of the identity
- OPKSSH_PLUGIN_EMAIL Email claim of the identity
- OPKSSH_PLUGIN_EMAIL_VERIFIED Optional claim that signals if the email address has been verified
- OPKSSH_PLUGIN_AUD Audience/client_id (aud) claim
- OPKSSH_PLUGIN_EXP Expiration (exp) claim
- OPKSSH_PLUGIN_NBF Not Before (nbf) claim
- OPKSSH_PLUGIN_IAT IssuedAt
- OPKSSH_PLUGIN_JTI JTI JWT ID

#### Misc

- OPKSSH_PLUGIN_PAYLOAD Based64-encoded ID Token payload (JSON)
- OPKSSH_PLUGIN_UPK Base64-encoded JWK of the user's public key in the PK Token
- OPKSSH_PLUGIN_IDT Compact-encoded ID Token
- OPKSSH_PLUGIN_PKT Compact-encoded PK Token
- OPKSSH_PLUGIN_CONFIG Base64 encoded bytes of the plugin config used in this call. Useful for debugging.
- OPKSSH_PLUGIN_GROUPS Groups claim (if present) of the identity.

### Handling missing or empty claims

Note that if an claim is not present we set to the empty string, "". For instance for an ID Token payload below, we set `OPKSSH_PLUGIN_AUD` and `OPKSSH_PLUGIN_EMAIL` to the empty string ("") since there is no `aud` claim and no email claim:

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

We do this to avoid situations where a policy plugin includes a claim to check if it present but does not require it. If we threw an error if it was not found then this would cause hard to debug policy failures if an ID Token is missing that claim.

If a policy plugin wishes to discriminate between claims which are missing or merely set to the empty string, they could use the `OPKSSH_PLUGIN_IDT` and parse the ID Token themselves.

## Example policy configs

### Match username to email address

This policy plugin allows ssh access as the principal (linux user) if the principal is the same as the username part of the email address in the ID Token, i.e. when email of the user fits the pattern `principal@example.com`.  For instance this would allow `ssh alice@hostname` if Alice's email address is `alice@example.com`.

To prevent issues where someone might get the email `root@example.com` it has a list of default linux principles always denies such as `root`, `admin`, `email`, `backup`...

The last part of the email address must match the value supplied at the commandline, for instance in the policy plugin config below, this would be `example.com`. If you wanted to use this for say `gmail.com` change this value from `example.com` to `gmail.com` in the config:

```yml
name: Match linux username to email username
command: /etc/opk/match-email.sh example.com
```

```bash
#!/usr/bin/env sh

principal="${OPKSSH_PLUGIN_U}"
email="${OPKSSH_PLUGIN_EMAIL}"
email_verified="${OPKSSH_PLUGIN_EMAIL_VERIFIED}"
req_domain="$1"

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
