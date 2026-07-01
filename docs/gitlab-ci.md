# SSH via GitLab CI

opkssh supports SSHing into servers from GitLab CI/CD jobs using GitLab's OpenID Connect (OIDC) ID tokens. This allows CI/CD pipelines to authenticate over SSH without managing static SSH keys or long-lived secrets.

## How it works

GitLab CI/CD can issue [OIDC ID tokens](https://docs.gitlab.com/ci/secrets/id_token_authentication/) to a job. These tokens prove the identity of a pipeline run, including claims such as the project path, branch/tag ref, and pipeline source.

When `opkssh login gitlab-ci` runs inside a GitLab CI environment, opkssh reads the ID token from the `OPENPUBKEY_JWT` environment variable and uses it to create an SSH certificate. The SSH server verifies the certificate against the server-side provider configuration and policy.

GitLab CI tokens are verified using OpenPubkey's GitLab CI provider. These tokens are GQ-bound (`GQ256`) rather than using the normal browser-login nonce flow, so the server must have a GitLab CI provider entry in `/etc/opk/providers`.

## Server setup

### 1. Install opkssh on the server

Follow the standard [installation instructions](../README.md#install-opkssh-on-a-server) to install opkssh on your server.

### 2. Add the GitLab CI provider

Add a GitLab CI provider entry to `/etc/opk/providers`. The second field should either be the GitLab CI marker `gitlab-ci` or the OpenPubkey PKToken audience used by your GitLab CI job.

Using the marker:

```bash
echo "https://gitlab.com gitlab-ci 24h" | sudo tee -a /etc/opk/providers
```

Or using the explicit audience from the GitLab CI token:

```bash
echo "https://gitlab.com OPENPUBKEY-PKTOKEN:ssh-deploy-prod 24h" | sudo tee -a /etc/opk/providers
```

If you also want to allow normal interactive GitLab logins, keep the normal GitLab provider entry as well:

```text
https://gitlab.com 8d8b7024572c7fd501f64374dec6bba37096783dfcd792b3988104be08cb6923 24h
https://gitlab.com gitlab-ci 24h
```

or:

```text
https://gitlab.com 8d8b7024572c7fd501f64374dec6bba37096783dfcd792b3988104be08cb6923 24h
https://gitlab.com OPENPUBKEY-PKTOKEN:ssh-deploy-prod 24h
```

### 3. Authorize a GitLab project and ref

Use `opkssh add` to allow a specific GitLab project and branch to SSH into the server as a given user. The identity typically matches GitLab's `sub` claim:

```text
project_path:<namespace>/<project>:ref_type:<branch|tag>:ref:<ref>
```

For example, to allow the `main` branch of `cgroschupp/opkssh-test` to log in as `root`:

```bash
sudo opkssh add root "project_path:cgroschupp/opkssh-test:ref_type:branch:ref:main" "https://gitlab.com"
```

This adds a line like this to `/etc/opk/auth_id`:

```text
root project_path:cgroschupp/opkssh-test:ref_type:branch:ref:main https://gitlab.com
```

Validate the server configuration:

```bash
sudo opkssh audit
sudo opkssh permissions check
```

## GitLab CI workflow

Your GitLab CI job needs an `id_tokens` entry that creates `OPENPUBKEY_JWT`. The `aud` value becomes part of the OpenPubkey PKToken audience.

Here is a minimal example that logs in with opkssh and SSHes into a remote server:

```yaml
stages:
  - test

test-ssh:
  id_tokens:
    OPENPUBKEY_JWT:
      aud: OPENPUBKEY-PKTOKEN:ssh-deploy-prod
  image: ubuntu
  stage: test
  script:
    - apt-get update && apt-get install -y curl openssh-client
    - curl -L -o /usr/local/bin/opkssh https://github.com/openpubkey/opkssh/releases/latest/download/opkssh-linux-amd64
    - chmod +x /usr/local/bin/opkssh
    - opkssh login gitlab-ci
    - opkssh inspect /root/.ssh/id_ecdsa-cert.pub
    - ssh -o StrictHostKeyChecking=accept-new root@your-server.example.com "echo 'Hello from GitLab CI'"
```

The example downloads the latest Linux amd64 opkssh binary from the official GitHub release. For other architectures, use the matching asset from the [latest release](https://github.com/openpubkey/opkssh/releases/latest).

### Key workflow requirements

- **`id_tokens.OPENPUBKEY_JWT`**: This must be configured so GitLab creates an OIDC ID token and exposes it as the `OPENPUBKEY_JWT` environment variable.
- **Audience must match server policy**: If the job uses `aud: OPENPUBKEY-PKTOKEN:ssh-deploy-prod`, the server should have either `https://gitlab.com OPENPUBKEY-PKTOKEN:ssh-deploy-prod 24h` or `https://gitlab.com gitlab-ci 24h` in `/etc/opk/providers`.
- **`opkssh login gitlab-ci`**: The `gitlab-ci` argument tells opkssh to use the GitLab CI provider. It reads `OPENPUBKEY_JWT` from the environment.
- **Server-side identity**: The identity in `/etc/opk/auth_id` must match the token's `sub` claim.

## Identity format

GitLab's default `sub` claim commonly has this format:

```text
project_path:<namespace>/<project>:ref_type:<branch|tag>:ref:<ref>
```

Examples:

| Pattern | Example |
|---------|---------|
| Project + branch | `project_path:mygroup/myproject:ref_type:branch:ref:main` |
| Project + tag | `project_path:mygroup/myproject:ref_type:tag:ref:v1.0.0` |

A GitLab CI token also contains additional claims such as `project_path`, `ref`, `ref_type`, `pipeline_source`, `job_project_path`, and `user_login`. The opkssh server policy usually authorizes the `sub` claim, but you can inspect the generated certificate to confirm the exact identity:

```bash
opkssh inspect /root/.ssh/id_ecdsa-cert.pub
```

Look for:

```text
Subject: project_path:cgroschupp/opkssh-test:ref_type:branch:ref:main
Issuer:  https://gitlab.com
```

## Troubleshooting

**Login fails in GitLab CI**
Make sure the job defines `id_tokens.OPENPUBKEY_JWT` and runs `opkssh login gitlab-ci` inside GitLab CI. The environment must contain `GITLAB_CI=true` and `OPENPUBKEY_JWT`.

**SSH connection rejected**
Check the server policy and provider configuration:

```bash
sudo cat /etc/opk/auth_id
sudo cat /etc/opk/providers
sudo opkssh audit
```

Verify that the identity in `/etc/opk/auth_id` matches the `Subject` shown by `opkssh inspect`.

**Audience mismatch**
If the token audience is `OPENPUBKEY-PKTOKEN:ssh-deploy-prod`, add a matching provider line:

```text
https://gitlab.com OPENPUBKEY-PKTOKEN:ssh-deploy-prod 24h
```

Alternatively, use the generic GitLab CI marker:

```text
https://gitlab.com gitlab-ci 24h
```

**Normal GitLab login works but GitLab CI fails**
Normal GitLab logins use the browser/OIDC nonce flow. GitLab CI uses GQ-bound tokens (`GQ256`). Ensure the server has a GitLab CI provider line (`gitlab-ci` or `OPENPUBKEY-PKTOKEN:*`) in `/etc/opk/providers`.

**Verify fails during SSH authentication**
Check the opkssh server log:

```bash
sudo tail -n 200 /var/log/opkssh.log
```

You can also test verification manually on the server:

```bash
typ=$(awk '{print $1}' /root/.ssh/id_ecdsa-cert.pub)
cert=$(awk '{print $2}' /root/.ssh/id_ecdsa-cert.pub)
sudo -u opksshuser /usr/local/bin/opkssh verify root "$cert" "$typ"
```
