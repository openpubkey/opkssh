# using the audit command

The opkssh [audit command](cli/opkssh_audit.d) is useful for catch and troubleshooting server side misconfigurations.
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
* The audit command does not currently support checking [policy plugins](policyplugins.m) or openssh server config (`sshd_config`).

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
