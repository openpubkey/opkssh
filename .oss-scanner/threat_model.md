# opkssh threat model

Guidance for Anthropic's OSS Scanner. Free text; maintainers may edit it between scans.

## What this project does

opkssh lets users SSH with an OpenID Connect identity (e.g. `alice@example.com`) instead of a
long-lived key. It has two halves:

- **Server side (`opkssh verify`)** — the security-critical half. sshd runs it as an
  `AuthorizedKeysCommand`, normally as the unprivileged `opksshuser`, sometimes as root. It receives the
  target username, the client's SSH certificate (which embeds a PK Token) and the key type, verifies the
  PK Token against the configured OpenID Providers, checks policy, and prints an authorized key line if
  access is allowed. Anything it prints is treated by sshd as an authorization decision.
- **Client side (`opkssh login`, `inspect`, `client provider add`, etc.)** — runs as the user on their
  own machine, performs an OIDC flow in the browser, and writes an SSH key and certificate under `~/.ssh`.

The cryptography and PK Token format come from the OpenPubkey library (github.com/openpubkey/openpubkey),
which is scanned separately; report library bugs there unless opkssh misuses the API.

## Where untrusted input enters

Treat these as attacker-controlled:

- The SSH certificate / public key and the requested principal (username) that sshd passes to
  `opkssh verify`. Any remote client can supply these without authenticating.
- Everything inside the PK Token: ID-token claims (`iss`, `aud`, `sub`, `email`, `groups`, `exp`, …),
  protected headers, signatures, the CIC, and any cosigner signature.
- Network responses from OpenID Providers (discovery documents, JWKS, userinfo) — assume an attacker may
  be on the network path or may control a non-configured issuer.
- Per-user policy files in a user's home directory (`~/.opk/auth_id`). They are read via
  `sudo -n opkssh readhome <user>`; a local user controls their own file and must not be able to grant
  access to *another* user's account or escalate through the sudo rule.
- Output of policy plugin commands, insofar as the input passed to them (token claims) is attacker-controlled.
- On the client: the OIDC redirect to the localhost callback server, and tokens returned by the provider.

Trusted (admin-controlled, root-owned): `/etc/opk/providers`, `/etc/opk/auth_id`, `/etc/opk/config.yml`,
`/etc/opk/policy.d/*` plugin configs, and the installer's arguments. Bugs that need an admin to write a
hostile config are low severity unless the file permissions model lets a non-admin write it.

## Components that matter most / least

Most important:
- `commands/verify.go`, `policy/` (enforcer, policy loaders, provider loader, validator, plugins),
  `policy/files/` (permission checks), `sshcert/`, and `main.go`'s verify path.
- The `readhome` sudo helper (`commands/readhome*.go`, `policy/multipolicyloader_unix.go`).
- `scripts/install-linux.sh` and `scripts/windows/` installers: the files and permissions they create
  (e.g. an installer that leaves `/etc/opk` writable by non-root is in scope).

Less important but in scope: `commands/login.go`, `logout.go`, `inspect.go`, `client_provider.go`,
`commands/config/` (client config handling), `audit` and `permissions` subcommands.

Out of scope: `test/`, `hack/`, `docs/`, `.github/`, `.forgejo/`, and generated mocks.

## Security properties we care about

1. `opkssh verify` never authorizes a login unless: the PK Token is validly signed by a provider listed
   in `/etc/opk/providers`, its audience matches that provider's client ID, the token is within the
   configured expiration policy, the SSH key presented is the one bound in the PK Token, and policy maps
   the identity to the requested principal.
2. A user's home policy can only grant access to that same user's account.
3. Nothing a remote client sends can make `verify` execute commands, read arbitrary files, or write files.
4. Malformed input fails closed (deny), never open.

## How to exercise it

- The image has opkssh installed at `/usr/local/bin/opkssh` via `scripts/install-linux.sh`, with
  `/etc/opk` populated and sshd configured to call `opkssh verify` as `opksshuser`. The real providers
  in `/etc/opk/providers` are unreachable without network, so test with the mock provider below.
- `go test ./...` runs the unit tests offline. `commands/verify_test.go` and `policy/*_test.go` show how
  to build PK Tokens with `providers.NewMockProvider` from OpenPubkey and feed them to the verifier.
- `test/integration` needs Docker and is not runnable inside the scanner; it is compiled only.

## How we rate severity

- **Critical:** remote authentication bypass — logging in as any user without a valid token from a
  configured provider, or as a principal policy does not grant; remote code execution in `verify`.
- **High:** a local user gaining another user's or root's access (via home policy, the `readhome` sudo
  rule, plugins or file-permission handling); accepting expired tokens or tokens for the wrong audience;
  token/key binding bypass.
- **Medium:** denial of service of `verify` that blocks all opkssh logins (crash, hang, unbounded
  resource use on attacker input); installer leaving security-relevant files with weak permissions;
  client-side bugs that leak the user's ID token or private key to another local user or website.
- **Low:** information disclosure in logs, other client-side issues, issues needing a hostile admin config.

## Reporting preferences

- Include a minimal reproducer: a Go test in the relevant package, or a shell transcript against the
  installed binary.
- Patches should be minimal and fix the root cause; a regression test is appreciated.
- Deduplicate by root cause, not by entry point.

## Known behaviour that is not a bug

- The default client IDs in `commands/config/default-client-config.yml` are public. opkssh is a public
  OAuth client; `client_secret` values there are not confidential.
- The client config file is mode 0644 by design.
- Fetched JWKS may be cached, so a rotated or revoked provider key can be trusted until the cache expires.
