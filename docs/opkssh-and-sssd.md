# Use opkssh in combination with sssd

In scenarions where the machines are already joined to a domain and where other `SSH` policies exist, `opkssh` login might run into issues.
The SSH policies will take precedence based on the file name within `sshd_config.d` and as such only the first matched policy will work.
The following steps give an example on how to combine  2 different policies (SSSD and OPKSSH) so that one is used as a fallback, incase the other fails.

## Scenario

- `ssh` public keys of the users are stored in Active directory (AD)
- `opkssh` installed on server and client
- ssh server connected to domain via `SSSD`
- only a specific group/groups are allowed to login via SSH to the servers

## Implementation on Server

- Add a custom policy under `/etc/ssh/sshd_config.d/50-ssh-domain-policy.conf` with the following contents.

    ```

    # Don't use authorized keys file from anyone.
    AuthorizedKeysFile      none

    # Don't trust user known host keys
    IgnoreUserKnownHosts yes

    # Rules for AD users
    Match Group ssh-users
    # Check if key exists in opkssh or in AD attribute "sshPublicKey"
    AuthorizedKeysCommand /etc/ssh/sshd_config.d/parse_keys.sh %u %k %t
    AuthorizedKeysCommandUser root
    AuthenticationMethods publickey
    ```
    - The rule above basically restricts ssh to a specific subset of users and when these users try to log in a custom command is executed that acquires the user's ssh public key from the respective providers

- Create another file under `/etc/ssh/sshd_config.d/parse_keys.sh` and set the rights to `700` with the following content

    ```
    #!/bin/bash

    # Script to verify the ssh keys via both opkssh and sssd
    # This is necessary to have a unified ssh policy that allows both


    # Check keys via opkssh first
    runuser -u opksshuser -- /usr/local/bin/opkssh verify $1 $2 $3

    # If above errors then check via sssd

    if [ "${PIPESTATUS[0]}" -ne 0 ]; then
        runuser -u nobody --  /usr/bin/sss_ssh_authorizedkeys $1
    fi
    ```
    - The script basically verifies with `opkssh` the user first and if the command fails then checks with `SSSD`. If both fail, then the login will be rejected. NOTE: `opkssh` requires multiple arguments, sssd requires only the username since the key is fethched from AD

- For `opkssh` instead of specifying each user from the group, use a  policy plugin. Create the following files, `/etc/opk/policy.d/domain-plugin.yml` and `/etc/opk/policy.d/match-email.sh`

    - Content of `domain-plugin.yml`. Set the correct rights and mode,  `chown root:opksshuser domain-olugin.yml` and `chmod 640 domain-plugin.yml`
-rwxr-xr-x 1 root opksshuser 470 Nov 24 17:26 match-email.sh
    ```
    name: Match linux username to email username
    command: /etc/opk/policy.d/match-email.sh <domain name> # example my-domain.com
    ```
    - content of `match-email.sh`, verifies if the email claim matches for the user and then allows it via `opkssh` else login is denined. Set the rights and mode, `chmod 755 match-email.sh && chown root:opksshuser match-email.sh`

    ```sh
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
    if [ "$expectedEmail" = "$email" ] ; then
    echo $email_verified
    echo "allow"
    exit 0
    else
    echo "deny"
    exit 1
    fi
    ```

- Restart SSSD and SSH, `systemctl restart sshd && systemctl restart sssd`

## Login

Now onto testing if the login works with both the methods.

- Get a ssh key via `opkssh login`
    - Example, the generated keys are stored in `C:\Users\user\.ssh\id_ecdsa-cert.pub` and corresponding secret key to `C:\Users\user\.ssh\id_ecdsa`
- Login with the key `ssh -v user@pascal.my-domain.com`. The login will succeed with the `opkssh` generated key, see debug output below
    ```
    debug1: kex_ext_info_check_ver: publickey-hostbound@openssh.com=<0>
    debug1: kex_ext_info_check_ver: ping@openssh.com=<0>
    debug1: SSH2_MSG_SERVICE_ACCEPT received
    debug1: Authentications that can continue: publickey
    debug1: Next authentication method: publickey
    debug1: Offering public key: C:\\Users\\user/.ssh/id_ecdsa ECDSA SHA256:1kiIlFWEH9d/o/lzWcb295DOGMT6mZ0ZMJfUiuhFLB0
    debug1: Authentications that can continue: publickey
    debug1: Offering public key: C:\\Users\\user/.ssh/id_ecdsa ECDSA-CERT SHA256:1kiIlFWEH9d/o/lzWcb295DOGMT6mZ0ZMJfUiuhFLB0
    debug1: Server accepts key: C:\\Users\\user/.ssh/id_ecdsa ECDSA-CERT SHA256:1kiIlFWEH9d/o/lzWcb295DOGMT6mZ0ZMJfUiuhFLB0
    Authenticated to pascal.my-domain.com ([19.18.0.31]:22) using "publickey".
    ```

- Now delete the generated ssh keys `rm C:\\Users\\user/.ssh/id_ecdsa*`
- Login with `ssh -v user@pascal.my-domain.com`, this time it should succeed but with keys fetched via `sssd`.

    ```
    debug1: get_agent_identities: agent returned 1 keys
    debug1: Will attempt key: C:\\Users\\user/.ssh/id_ed25519 ED25519 SHA256:CLIXCc2NIbBTpMOEzex/vbXpihzRoFc7KxQhU8C46a8 agent
    Authenticated to pascal.my-domain.com ([19.18.0.31]:22) using "publickey".
    debug1: Remote: /etc/ssh/sshd_config.d/parse_keys.sh %u %k %t:2: key options: agent-forwarding port-forwarding pty user-rc x11-forwarding
    debug1: Remote: /etc/ssh/sshd_config.d/parse_keys.sh %u %k %t:2: key options: agent-forwarding port-forwarding pty user-rc x11-forwarding
    debug1: pledge: fork
    ```
