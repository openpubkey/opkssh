# using the audit command

The opkssh [audit command](cli/opkssh_audit.md) is useful for catch and troubleshooting server side misconfigurations.
It checks the `auth_id` policy files (`/etc/opk/auth_id`, `~/opk/auth_id`) and the providers config file (`/etc/opk/providers`).

To perform run the command: `sudo opkssh audit`

```bash
$sudo ./opkssh audit
[sudo] password for e0: 

validating /etc/opk/auth_id...
[OK] SUCCESS : e0 e@example.com https://accounts.google.com (issuer matches provider entry)
[OK] SUCCESS : ro oidc:"https://acme.com/groups":ssh-users https://accounts.google.com (issuer matches provider entry)

validating /home/e0/.opk/auth_id...
[OK] SUCCESS : e0 e@example.com https://accounts.google.com (issuer matches provider entry)

validating /home/alice2/.opk/auth_id...
[OK] SUCCESS : alice2 alice@example.com https://accounts.google.com (issuer matches provider entry)
2026/01/18 12:31:26 Attempting OS-specific version detection for: debian

=== SUMMARY ===
Total Entries Tested:  4
Successful:            4
Warnings:              0
Errors:                0

Exit Code: 0 (no issues detected)
```

**Tips:**

* It must be run as root or sudo, because it requires root permissions to read all the config files.
* Use the json flag (`--json`) to get finer grained information. The JSON output of audit is useful information to supply in a bug report as it contains system details such as OS and opkssh version.
* If the configuration is correct, audit returns error code 0. If it encounters errors or warnings it returns a non-zero error code.

**Known limitations:**

* The audit command currently only checks server side configurations. It does not report on client-side configurations.
* The audit command does not currently support checking [policy plugins](policyplugins.md) or openssh server config (`sshd_config`).

## Default client IDs

opkssh ships with default client IDs for Google, Microsoft, GitLab and hello.coop for testing and development, and the installers write them to `/etc/opk/providers`.
They should not be used in production, as they allow the opkssh project to have control over your redirect URIs.

`opkssh audit` reports a warning for each row in the providers file that uses one of opkssh's default client IDs, whatever the issuer, and exits with code 1:

```bash
$ sudo opkssh audit
warning: /etc/opk/providers trusts https://accounts.google.com with opkssh's default client ID 206584157355-7cbe4s640tvm7naoludob4ut1emii7sf.apps.googleusercontent.com
  opkssh's default client IDs are intended for testing and should not be used in production. To use your own client IDs, see https://github.com/openpubkey/opkssh/blob/main/docs/audit.md#default-client-ids

validating /etc/opk/auth_id...
[OK] SUCCESS : root alice@example.com https://accounts.google.com (issuer matches provider entry)

=== SUMMARY ===
Total Entries Tested:  1
Successful:            1
Warnings:              0
Errors:                0
Provider Warnings:     1

Exit Code: 1 (warnings detected)
Error: audit completed and discovered warnings
```

To use your own client IDs, for each provider you use:

1. Register your own OAuth client with the provider:

   | Provider | Issuer | How to register |
   |---|---|---|
   | Google | `https://accounts.google.com` | [Google guide](providers/google.md) |
   | Microsoft | `https://login.microsoftonline.com/{TENANT ID}/v2.0` | [Entra ID (Azure) guide](providers/azure.md) |
   | GitLab | `https://gitlab.com` | Create an application under **Edit profile > Access > Applications** on gitlab.com, with the settings in the [self-hosted GitLab guide](gitlab-selfhosted.md#create-an-oauth-application-in-gitlab) |
   | hello.coop | `https://issuer.hello.coop` | Register an application in the [Hellō console](https://console.hello.coop/) and allow the redirect URIs below |
   | Others | | See [docs/providers](providers/) |

   opkssh logs in through these redirect URIs, so allow all three:

   ```text
   http://localhost:3000/login-callback
   http://localhost:10001/login-callback
   http://localhost:11110/login-callback
   ```

2. Replace opkssh's client ID with yours in `/etc/opk/providers`.
3. Give your users a client config that uses the same client ID (see the [client config file](../README.md#client-config-file)).

Remove the rows for providers you don't use.

In the JSON output, these warnings are listed under `providers_file.warnings`, and `ok` is `false`.

## audit vs permissions

The `opkssh audit` and `opkssh permissions` commands are related but serve different purposes:

| | `opkssh audit` | `opkssh permissions check` |
|---|---|---|
| **Purpose** | Validate policy file *contents* against provider definitions | Check and *fix* filesystem permissions/ACLs |
| **Focus** | Are issuers valid? Do entries match providers? | Are file modes, ownership and ACLs correct? |
| **User home dirs** | Enumerates and audits all user `~/.opk/auth_id` files | Does **not** check user policy files |
| **Modifies files** | Never (read-only) | `permissions fix` can repair permissions |
| **Output** | Human-readable table or JSON (`--json`) | Problem list or planned actions |

**When to use which:**

* **`opkssh audit`** — Run after editing policy or provider files to verify the configuration is correct. Also useful for generating a JSON report for bug reports.
* **`opkssh permissions check`** — Run after installation or upgrades to verify that file permissions and ACLs are correct. If problems are found, run `opkssh permissions fix` to repair them.

Both commands check the permissions on the system policy file (`/etc/opk/auth_id` on Linux, `%ProgramData%\opk\auth_id` on Windows) using the same shared logic, so their permission-related findings will be consistent.

## JSON output

To get the full audit report use the `--json` flag:

```bash
sudo opkssh audit --json
```

If you just want the json so that another tool can ingest it, then pipe std err to /dev/null:

```bash
sudo opkssh audit --json 2> /dev/null
```

Example json output:

```bash
$ sudo opkssh audit --json
[sudo] password for e0: 

validating /etc/opk/auth_id...

validating /home/e0/.opk/auth_id...

validating /home/alice2/.opk/auth_id...
2026/01/18 14:21:11 Attempting OS-specific version detection for: debian
{
  "ok": true,
  "username": "root",
  "providers_file": {
    "file_path": "/etc/opk/providers",
    "error": ""
  },
  "system_policy": {
    "file_path": "/etc/opk/auth_id",
    "rows": [
      {
        "status": "SUCCESS",
        "hints": [],
        "principal": "e0",
        "identity_attr": "e@example.com",
        "issuer": "https://accounts.google.com",
        "reason": "issuer matches provider entry",
        "line_number": 1
      },
      {
        "status": "SUCCESS",
        "hints": [],
        "principal": "ro",
        "identity_attr": "oidc:\"https://acme.com/groups\":ssh-users",
        "issuer": "https://accounts.google.com",
        "reason": "issuer matches provider entry",
        "line_number": 2
      }
    ],
    "error": "",
    "perms_error": ""
  },
  "home_policy": [
    {
      "file_path": "/home/e0/.opk/auth_id",
      "rows": [
        {
          "status": "SUCCESS",
          "hints": [],
          "principal": "e0",
          "identity_attr": "e@example.com",
          "issuer": "https://accounts.google.com",
          "reason": "issuer matches provider entry",
          "line_number": 1
        }
      ],
      "error": "",
      "perms_error": ""
    },
    {
      "file_path": "/home/alice2/.opk/auth_id",
      "rows": [
        {
          "status": "SUCCESS",
          "hints": [],
          "principal": "alice2",
          "identity_attr": "alice@example.com",
          "issuer": "https://accounts.google.com",
          "reason": "issuer matches provider entry",
          "line_number": 1
        }
      ],
      "error": "",
      "perms_error": ""
    }
  ],
  "opk_version": "unversioned",
  "openssh_version": "OpenSSH_9.6",
  "os_info": "debian"
}
```
