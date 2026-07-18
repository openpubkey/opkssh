# SSH via Forgejo Actions (Codeberg)

opkssh supports SSHing into servers from [Forgejo Actions](https://forgejo.org/docs/latest/user/actions/) workflows, for example on [Codeberg](https://codeberg.org), using Forgejo's OpenID Connect (OIDC) tokens. This lets your CI/CD pipelines authenticate over SSH without managing static SSH keys or secrets.

Forgejo Actions OIDC tokens require Forgejo v15.0 or later. Codeberg supports them out of the box.

## How it works

Forgejo can issue [OIDC tokens](https://forgejo.org/docs/latest/user/actions/security-openid-connect/) that prove the identity of a workflow run. opkssh uses these tokens to create SSH certificates. The SSH server verifies the certificate against a policy that authorizes specific repositories and refs.

When `opkssh login forgejo` runs inside a Forgejo Actions environment, it automatically detects the environment variables `ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN` and uses them to obtain an OIDC token from your Forgejo instance.

The issuer is specific to your instance. It is always the instance URL followed by `/api/actions`, for example `https://codeberg.org/api/actions`. opkssh derives the issuer automatically from the workflow environment, so `opkssh login forgejo` works on any Forgejo instance, including self-hosted ones, without any client configuration. The alias `codeberg` works as well.

## Server setup

### 1. Install opkssh on the server

Follow the standard [installation instructions](../README.md#installing-on-a-linux-server) to install opkssh on your server.

### 2. Add the Forgejo Actions provider

Add your Forgejo instance's Actions OIDC provider to the providers file on the server. For Codeberg:

```bash
echo "https://codeberg.org/api/actions codeberg oidc" >> /etc/opk/providers
```

For a self-hosted Forgejo instance, use your instance URL followed by `/api/actions`:

```bash
echo "https://git.example.com/api/actions forgejo oidc" >> /etc/opk/providers
```

The second column (client ID) is required but not used for this provider. We recommend the `oidc` expiration policy so the SSH key expires together with the short-lived Forgejo token.

### 3. Authorize a repository

Use `opkssh add` to allow a specific repository and branch to SSH into the server as a given user. For repositories which had Forgejo Actions enabled on Forgejo v16 or later, the identity takes the form `repo:OWNER-OWNERID/REPO-REPOID:ref:REF` with the immutable numeric owner and repository IDs appended (see [Identity format](#identity-format) below for how to find the IDs and for the legacy format without IDs).

For example, to allow the `main` branch of `myorg/myrepo` (owner ID 9, repository ID 84) on Codeberg to log in as the `deploy` user:

```bash
opkssh add deploy "repo:myorg-9/myrepo-84:ref:refs/heads/main" "https://codeberg.org/api/actions"
```

You can also authorize a specific tag, glob within separators, or pull requests:

```bash
# Authorize a specific tag
opkssh add deploy "repo:myorg-9/myrepo-84:ref:refs/tags/v1.0.0" "https://codeberg.org/api/actions"

# Authorize all single word and staging branches
opkssh add deploy "repo:myorg-9/myrepo-84:ref:refs/heads/*" "https://codeberg.org/api/actions"
opkssh add deploy "repo:myorg-9/myrepo-84:ref:refs/heads/staging/*" "https://codeberg.org/api/actions"

# Authorize pull requests
opkssh add deploy "repo:myorg-9/myrepo-84:pull_request" "https://codeberg.org/api/actions"
```

`**` is not supported. The glob patterns follow [go's file Match](https://pkg.go.dev/path#Match). Do not use globs to avoid looking up the owner and repository IDs (for example `repo:myorg-*/myrepo-*`), since an attacker could register an account or repository whose *name* matches such a pattern.

## Forgejo Actions workflow

Your workflow needs `enable-openid-connect: true`, at the workflow level or at the job level, so that Forgejo provides the OIDC token. Here is an example workflow that SSHes into a remote server:

```yaml
name: Deploy via SSH

on:
  push:
    branches:
      - main

enable-openid-connect: true

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
    - name: Checkout
      uses: actions/checkout@v4

    - name: Install opkssh
      run: |
        curl -sSLf https://github.com/openpubkey/opkssh/releases/latest/download/opkssh-linux-amd64 -o opkssh
        chmod +x opkssh

    - name: Login
      run: ./opkssh login forgejo

    - name: SSH into server
      run: |
        ssh -o StrictHostKeyChecking=accept-new deploy@your-server.example.com "echo 'Hello from Forgejo Actions'"
```

### Key workflow requirements

- **`enable-openid-connect: true`**: This is required for Forgejo to provide the OIDC token to the workflow. Without it, the login step will fail. It can be set at the workflow level or on an individual job.
- **`opkssh login forgejo`**: The `forgejo` argument (or its alias `codeberg`) tells opkssh to use the Forgejo Actions OIDC provider of the current workflow environment. This works on any Forgejo instance and does not require any client configuration.

## Identity format

The identity string used in `opkssh add` for Forgejo Actions must match the `sub` claim in Forgejo's OIDC token exactly. For repositories which had Forgejo Actions enabled on Forgejo v16 or later, the immutable numeric owner and repository IDs are appended to the names so that an identity cannot be hijacked by re-creating a renamed account or repository:

| Pattern | Example |
|---------|---------|
| Repository + branch | `repo:myorg-9/myrepo-84:ref:refs/heads/main` |
| Repository + tag | `repo:myorg-9/myrepo-84:ref:refs/tags/v1.0.0` |
| Pull request | `repo:myorg-9/myrepo-84:pull_request` |

You can look up the two IDs via the repository API of your instance:

```bash
curl -s https://codeberg.org/api/v1/repos/myorg/myrepo | jq '.owner.id, .id'
```

Alternatively, run `opkssh login forgejo --print-id-token` once in your workflow to print the exact `sub` value to use in the policy.

Repositories which had Forgejo Actions enabled prior to Forgejo v16 keep the legacy subject format without IDs (`repo:myorg/myrepo:ref:refs/heads/main`). You can convert such a repository to the ID format by disabling and then re-enabling Forgejo Actions in the repository settings. This conversion is permanent and cannot be undone.

For the full list of available claims, see the [Forgejo documentation on OIDC](https://forgejo.org/docs/latest/user/actions/security-openid-connect/).

## Troubleshooting

**Login fails with "environment variable not set"**
Ensure your workflow (or job) has `enable-openid-connect: true` set. It is not enabled by default. Note that OIDC tokens require Forgejo v15.0 or later.

**Login fails with "not a Forgejo Actions environment"**
The workflow is running somewhere else (for example GitHub Actions). Use `opkssh login github` for GitHub Actions.

**SSH connection rejected**
Check the policy on the server. Run `sudo cat /etc/opk/auth_id` and verify the identity string matches the repository and ref of the workflow. A common pitfall is the owner/repository IDs in the `sub` claim: the policy must contain `repo:myorg-9/myrepo-84:ref:...`, not `repo:myorg/myrepo:ref:...` (see [Identity format](#identity-format)). Run `opkssh login forgejo --print-id-token` in the workflow to see the exact `sub` value, and `sudo opkssh audit` to validate the server configuration.

**"Provider not found" error**
Make sure `/etc/opk/providers` contains your instance's Forgejo Actions provider line, e.g.:
```
https://codeberg.org/api/actions codeberg oidc
```
