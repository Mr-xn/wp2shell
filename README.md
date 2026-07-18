# wp2shell PoC 
This is an HTTP/HTTPS wp2shell PoC with advanced capabilities for impact demonstration on improperly conifgured wordpress sites. 


                 ____      _          _ _
 __      ___ __ |___ \ ___| |__   ___| | |
 \ \ /\ / / '_ \  __) / __| '_ \ / _ \ | |
  \ V  V /| |_) |/ __/\__ \ | | |  __/ | |
   \_/\_/ | .__/|_____|___/_| |_|\___|_|_|
          |_|   CVE-2026-63030

  Pre-Auth RCE in WordPress Core REST API

positional arguments:
  target                WordPress URL (http:// or https://)

options:
  -h, --help            show this help message and exit
  --check               Non-destructive vulnerability probe only
  --exploit             Full pre-auth RCE chain
  --shell               Deploy shell with known admin creds
  --cleanup             Remove deployed webshell
  --extract SQL         Extract data via blind SQLi (e.g. "SELECT user_login FROM wp_users LIMIT 1")
  --proxy PROXY         HTTP proxy (e.g. http://127.0.0.1:8080)
  --timeout TIMEOUT     HTTP timeout seconds (default: 30)
  --table-prefix TABLE_PREFIX
                        WP table prefix (default: wp_)
  --webroot WEBROOT     Server webroot for OUTFILE (default: /var/www/html)
  --shell-key SHELL_KEY
                        Webshell auth key (random if omitted)
  --admin-user ADMIN_USER
                        Admin username (for --shell/--cleanup)
  --admin-pass ADMIN_PASS
                        Admin password (for --shell/--cleanup)
  --skip-outfile        Skip SELECT INTO OUTFILE attempt
  --sleep SLEEP         SLEEP duration for blind SQLi (default: 0.15)
  -v, --verbose         Verbose output
