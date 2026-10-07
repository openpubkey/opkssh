## opkssh cache clean

Remove stale JWKS cache entries

### Synopsis

Clean removes cache entries older than max-age.

Without max-age, clean uses fallback_max_age from the server configuration.
Run this command periodically as the opkssh user to bound cache disk use.

```
opkssh cache clean [max-age] [flags]
```

### Options

```
  -h, --help   help for clean
```

### Options inherited from parent commands

```
      --config-path string   Path to the server config file. Default: /etc/opk/config.yml (default "/etc/opk/config.yml")
```

### SEE ALSO

* [opkssh cache](opkssh_cache.md) - Manage the JWKS cache used by opkssh verify
