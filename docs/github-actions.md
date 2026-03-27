# SSH via GitHub Actions

opkssh supports SSHing into servers from GitHub Actions workflows using GitHub's OpenID Connect (OIDC) tokens. This allows your CI/CD pipelines to authenticate over SSH without managing static SSH keys or secrets.

## How it works

GitHub Actions can issue [OIDC tokens](https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect) that prove the identity of a workflow run. opkssh uses these tokens to create SSH certificates. The SSH server verifies the certificate against a policy that authorizes specific repositories and refs.

When `opkssh login github` runs inside a GitHub Actions environment, it automatically detects the environment variables `ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN` and uses them to obtain an OIDC token from `https://token.actions.githubusercontent.com`.

## Server setup

### 1. Install opkssh on the server

Follow the standard [installation instructions](../README.md#install-opkssh-on-a-server) to install opkssh on your server.

### 2. Add the GitHub Actions provider

Add the GitHub Actions OIDC provider to the providers file on the server:

```bash
echo "https://token.actions.githubusercontent.com github oidc" >> /etc/opk/providers
```

### 3. Authorize a repository

Use `opkssh add` to allow a specific repository and branch to SSH into the server as a given user. The identity takes the form `repo:OWNER/REPO:ref:REF`.

For example, to allow the `main` branch of `myorg/myrepo` to log in as the `deploy` user:

```bash
opkssh add deploy "repo:myorg/myrepo:ref:refs/heads/main" "https://token.actions.githubusercontent.com"
```

You can also authorize all branches by omitting the ref portion, or match a specific tag:

```bash
# Authorize all refs
opkssh add deploy "repo:myorg/myrepo:ref:*" "https://token.actions.githubusercontent.com"

# Authorize a specific tag
opkssh add deploy "repo:myorg/myrepo:ref:refs/tags/v1.0.0" "https://token.actions.githubusercontent.com"
```

## GitHub Actions workflow

Your workflow needs the `id-token: write` permission so that GitHub provides the OIDC token. Here is an example workflow that SSHes into a remote server:

```yaml
name: Deploy via SSH

on:
  push:
    branches:
      - main

permissions: {}

jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
    - name: Checkout
      uses: actions/checkout@v5
      with:
        persist-credentials: false

    - name: Install opkssh
      run: curl -sSLf https://raw.githubusercontent.com/openpubkey/opkssh/main/scripts/install-linux.sh | bash

    - name: Login
      run: opkssh login github

    - name: SSH into server
      run: |
        ssh -o StrictHostKeyChecking=accept-new user@your-server.example.com "echo 'Hello from GitHub Actions'"
```

### Key workflow requirements

- **`id-token: write` permission**: This is required for GitHub to provide the OIDC token to the workflow. Without it, the login step will fail.
- **`opkssh login github`**: The `github` argument tells opkssh to use the GitHub Actions OIDC provider. This is automatically available inside GitHub Actions and does not require any client configuration.

## Identity format

The identity string used in `opkssh add` for GitHub Actions follows the format of the `sub` claim in GitHub's OIDC token. Common patterns include:

| Pattern | Example |
|---------|---------|
| Repository + branch | `repo:myorg/myrepo:ref:refs/heads/main` |
| Repository + tag | `repo:myorg/myrepo:ref:refs/tags/v1.0.0` |
| Repository + pull request | `repo:myorg/myrepo:ref:refs/pull/42/merge` |

For the full list of available claims, see the [GitHub documentation on OIDC token claims](https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect#understanding-the-oidc-token).

## Troubleshooting

**Login fails with "error creating github op"**
Ensure your workflow has the `id-token: write` permission set. This is not granted by default.

**SSH connection rejected**
Check the policy on the server. Run `sudo cat /etc/opk/auth_id` and verify the identity string matches the repository and ref of the workflow. Run `sudo opkssh audit` to validate the server configuration.

**"Provider not found" error**
Make sure `/etc/opk/providers` contains the GitHub Actions provider line:
```
https://token.actions.githubusercontent.com github oidc
```
