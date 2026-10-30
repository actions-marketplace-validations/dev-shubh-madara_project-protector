"""Consent-based LIVE check. Localhost only. Read-only, harmless requests.

Two levels:
  * normal  - about 25 ordinary GET requests (fast; used by the hook, CI and the scoreboard).
  * deep    - a thorough 2-3 minute sweep of YOUR running app: a large list of sensitive
              paths, every security header, cookie flags, CORS, HTTP methods, a crawl of your
              own pages, and read-only reflection / SQL-error canaries.

Even in deep mode it NEVER floods the server, guesses passwords, runs destructive payloads,
changes or deletes data, or contacts any address other than the localhost one you confirmed.
Your code is never executed by CipherBloom; the app must already be running by itself.
"""
from __future__ import annotations

import ipaddress
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from .files import iter_files, read_text, rel
from .models import Finding

CONSENT_TEXT = """
CipherBloom Guardian - LIVE CHECK CONSENT
-----------------------------------------
Target : {target}
Mode   : {mode}, read-only, localhost only

{summary}

It will NOT: flood the server, guess passwords, run destructive payloads, change or
delete data, or contact any address except the one above. Your code is never executed
by CipherBloom; the app must already be running by itself.
"""
NORMAL_SUMMARY = """This will send about 25 ordinary GET requests to the address above to look for:
  * exposed files (.env, .git, backups)      * missing security headers
  * CORS that trusts every website           * debug pages / stack traces
  * directory listings and cookie flags"""
DEEP_SUMMARY = """This DEEP sweep takes about 2-3 minutes and sends several hundred slow,
read-only GET requests to the address above to look for:
  * ~150 sensitive files (.env, .git/.svn, backups, dumps, keys, CI secrets, logs)
  * every modern security header            * every cookie's flags
  * CORS that trusts other sites            * dangerous HTTP methods (TRACE/PUT/DELETE)
  * debug consoles and stack traces         * a crawl of your own linked pages
  * harmless reflection and SQL-error canaries (a marker string and a single quote only)"""
PHRASE = "I OWN THIS"

# How long the deep sweep should aim to take, so it stays polite and thorough rather than a flood.
DEEP_TARGET_SECONDS = 150
DEEP_MIN_SECONDS = 120


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def is_loopback(host):
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    if not infos:
        return False
    for info in infos:
        try:
            if not ipaddress.ip_address(info[4][0].split("%")[0]).is_loopback:
                return False
        except ValueError:
            return False
    return True


def validate_target(url):
    p = urllib.parse.urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("Target must look like http://localhost:8000")
    if not is_loopback(p.hostname):
        raise ValueError(
            "Refusing to test '%s'. Version 0.1 only tests localhost / 127.0.0.1 so it can never be "
            "used against someone else's site." % p.hostname)
    return "%s://%s" % (p.scheme, p.netloc)


def ask_consent(target, accepted_flag, deep=False):
    print(CONSENT_TEXT.format(target=target, mode="DEEP sweep (2-3 min)" if deep else "quick",
                              summary=DEEP_SUMMARY if deep else NORMAL_SUMMARY))
    if accepted_flag:
        print("Consent given with --yes-i-own-this.\n")
        return True
    if not sys.stdin.isatty():
        print("No interactive terminal. Re-run with --yes-i-own-this to give consent.")
        return False
    answer = input("Type  %s  to confirm this is YOUR app on YOUR computer: " % PHRASE).strip()
    return answer == PHRASE


def fetch(url, headers=None, timeout=6, method="GET"):
    req = urllib.request.Request(
        url, method=method,
        headers=dict({"User-Agent": "CipherBloom-Guardian/0.1 (localhost audit)"}, **(headers or {})))
    try:
        resp = _OPENER.open(req, timeout=timeout)
        status, hdrs, body = resp.status, resp.headers, resp.read(8000)
    except urllib.error.HTTPError as e:
        status, hdrs = e.code, e.headers
        try:
            body = e.read(8000)
        except OSError:
            body = b""
    except (urllib.error.URLError, OSError, ValueError):
        return None
    return status, {k.lower(): v for k, v in hdrs.items()}, body.decode("utf-8", "replace"), hdrs


def _not_html(h):
    return "html" not in h.get("content-type", "").lower()


# ---------------------------------------------------------------------------
# Sensitive-file lists.  Each entry: (path, severity, title, validator(body, headers)).
# The validator keeps false positives down: a 200 is not enough, the body must look real.
# ---------------------------------------------------------------------------
def _env_like(b, h):
    return _not_html(h) and re.search(r"(?m)^\s*[A-Z_][A-Z0-9_]*\s*=", b) is not None


def _text_has(*needles):
    def f(b, h):
        low = b.lower()
        return _not_html(h) and any(n in low for n in needles)
    return f


NORMAL_PROBES = [
    ("/.env", "critical", "Your .env file is downloadable", _env_like),
    ("/.env.local", "critical", "Your .env.local file is downloadable", _env_like),
    ("/.git/config", "high", "Your .git folder is public (source code can be rebuilt)",
     lambda b, h: "[core]" in b),
    ("/.git/HEAD", "high", "Your .git folder is public (source code can be rebuilt)",
     lambda b, h: b.startswith("ref:")),
    ("/backup.zip", "high", "A backup archive is downloadable", lambda b, h: _not_html(h) and b.startswith("PK")),
    ("/db.sqlite3", "high", "Your database file is downloadable", lambda b, h: b.startswith("SQLite format")),
    ("/.aws/credentials", "critical", "AWS credentials file is downloadable", _text_has("aws_access_key_id")),
    ("/docker-compose.yml", "medium", "docker-compose.yml is downloadable",
     lambda b, h: _not_html(h) and ("services:" in b)),
    ("/.DS_Store", "low", ".DS_Store leaks your folder layout", lambda b, h: b.startswith("\x00\x00\x00\x01Bud1")),
]

# Extra paths the DEEP sweep adds on top of NORMAL_PROBES.
DEEP_PROBES = [
    # more env / secret files
    ("/.env.production", "critical", ".env.production is downloadable", _env_like),
    ("/.env.development", "high", ".env.development is downloadable", _env_like),
    ("/.env.example", "info", ".env.example is public (usually fine)", _env_like),
    ("/.env.bak", "critical", "A .env backup is downloadable", _env_like),
    ("/config/.env", "critical", "config/.env is downloadable", _env_like),
    ("/app/.env", "critical", "app/.env is downloadable", _env_like),
    ("/.envrc", "high", ".envrc (direnv) is downloadable", lambda b, h: "export " in b),
    # version control
    ("/.git/logs/HEAD", "high", ".git logs are public (commit history exposed)",
     lambda b, h: re.search(r"[0-9a-f]{40}", b) is not None),
    ("/.git/index", "high", ".git index is downloadable", lambda b, h: b.startswith("DIRC")),
    ("/.gitignore", "info", ".gitignore is public (usually fine, reveals structure)",
     lambda b, h: _not_html(h) and bool(b.strip())),
    ("/.svn/entries", "high", ".svn metadata is public", lambda b, h: _not_html(h)),
    ("/.hg/requires", "medium", "Mercurial .hg folder is public", _text_has("revlog")),
    # backups / dumps / archives
    ("/backup.sql", "critical", "A SQL dump is downloadable", _text_has("insert into", "create table")),
    ("/dump.sql", "critical", "A SQL dump is downloadable", _text_has("insert into", "create table")),
    ("/database.sql", "critical", "A SQL dump is downloadable", _text_has("insert into", "create table")),
    ("/backup.tar.gz", "high", "A backup archive is downloadable", lambda b, h: b.startswith("\x1f\x8b")),
    ("/backup.zip.bak", "high", "A backup archive is downloadable", lambda b, h: _not_html(h) and b.startswith("PK")),
    ("/site.zip", "high", "A site archive is downloadable", lambda b, h: _not_html(h) and b.startswith("PK")),
    ("/www.zip", "high", "A site archive is downloadable", lambda b, h: _not_html(h) and b.startswith("PK")),
    ("/public.zip", "medium", "A public.zip archive is downloadable", lambda b, h: _not_html(h) and b.startswith("PK")),
    ("/db.sql", "critical", "A SQL dump is downloadable", _text_has("insert into", "create table")),
    ("/db.sqlite", "high", "Your database file is downloadable", lambda b, h: b.startswith("SQLite format")),
    ("/database.sqlite", "high", "Your database file is downloadable", lambda b, h: b.startswith("SQLite format")),
    ("/data.db", "high", "Your database file is downloadable", lambda b, h: b.startswith("SQLite format")),
    # cloud / CI / deploy secrets
    ("/.npmrc", "high", ".npmrc may contain an auth token", _text_has("_authtoken", "//registry")),
    ("/.pypirc", "high", ".pypirc may contain upload credentials", _text_has("[pypi]", "password")),
    ("/.dockercfg", "high", "Docker auth file is downloadable", _text_has("auth")),
    ("/.docker/config.json", "high", "Docker auth config is downloadable", _text_has("auths")),
    ("/.netrc", "high", ".netrc may contain login credentials", _text_has("machine", "login", "password")),
    ("/id_rsa", "critical", "A private SSH key is downloadable", _text_has("private key")),
    ("/.ssh/id_rsa", "critical", "A private SSH key is downloadable", _text_has("private key")),
    ("/server.key", "critical", "A TLS private key is downloadable", _text_has("private key")),
    ("/private.key", "critical", "A private key is downloadable", _text_has("private key")),
    ("/.github/workflows/deploy.yml", "medium", "CI workflow is downloadable", _text_has("jobs:", "runs-on")),
    ("/.circleci/config.yml", "medium", "CI config is downloadable", _text_has("version:", "jobs")),
    ("/.travis.yml", "low", "CI config is downloadable", _text_has("language:", "script")),
    # app config / framework files
    ("/config.py", "high", "config.py is downloadable (may hold secrets)", _text_has("secret", "key", "password", "token")),
    ("/settings.py", "high", "settings.py is downloadable (may hold secrets)", _text_has("secret_key", "database")),
    ("/config.json", "medium", "config.json is downloadable", _text_has("secret", "key", "password", "token")),
    ("/config.yml", "medium", "config.yml is downloadable", _text_has("secret", "password", "token")),
    ("/config.yaml", "medium", "config.yaml is downloadable", _text_has("secret", "password", "token")),
    ("/appsettings.json", "high", "appsettings.json is downloadable", _text_has("connectionstrings", "password")),
    ("/web.config", "medium", "web.config is downloadable", _text_has("<configuration")),
    ("/wp-config.php", "critical", "wp-config.php is downloadable", _text_has("db_password", "define(")),
    ("/phpinfo.php", "high", "phpinfo() is exposed", _text_has("phpinfo()", "php version")),
    ("/.htpasswd", "high", ".htpasswd (password hashes) is downloadable", lambda b, h: ":" in b and _not_html(h)),
    ("/composer.json", "info", "composer.json is public (reveals dependencies)", _text_has("require")),
    ("/package.json", "info", "package.json is public (reveals dependencies)", _text_has("dependencies", "\"name\"")),
    ("/requirements.txt", "info", "requirements.txt is public (reveals dependencies)",
     lambda b, h: _not_html(h) and re.search(r"(?m)^[a-zA-Z0-9_.-]+[=><~]", b) is not None),
    ("/Dockerfile", "low", "Dockerfile is downloadable", _text_has("from ", "run ")),
    ("/Makefile", "low", "Makefile is downloadable", lambda b, h: _not_html(h) and ":" in b),
    # editor / temp / swap leftovers
    ("/index.php.bak", "high", "A .bak source file is downloadable", _not_html),
    ("/app.py.bak", "high", "A .bak source file is downloadable", _not_html),
    ("/.index.php.swp", "medium", "A vim swap file leaks source", lambda b, h: "b0VIM" in b[:40]),
    ("/core", "low", "A core dump may be downloadable", lambda b, h: _not_html(h) and b.startswith("\x7fELF")),
    # logs
    ("/error.log", "medium", "An error log is downloadable", _text_has("error", "traceback", "exception")),
    ("/debug.log", "medium", "A debug log is downloadable", lambda b, h: _not_html(h) and bool(b.strip())),
    ("/logs/app.log", "medium", "An app log is downloadable", lambda b, h: _not_html(h) and bool(b.strip())),
    ("/npm-debug.log", "low", "npm debug log is downloadable", _text_has("npm")),
    # misc info leaks
    ("/robots.txt", "info", "robots.txt lists hidden paths (often fine)", lambda b, h: "disallow" in b.lower()),
    ("/sitemap.xml", "info", "sitemap.xml is public (usually fine)", _text_has("<urlset", "<url>")),
    ("/.well-known/security.txt", "info", "security.txt is public (good practice)", _text_has("contact:")),
    ("/server-status", "high", "Apache server-status is exposed", _text_has("apache server status")),
    ("/actuator/env", "critical", "Spring actuator /env exposes config + secrets", _text_has("propertysources", "systemproperties")),
    ("/actuator/health", "low", "Spring actuator is exposed", _text_has("\"status\"")),
    ("/metrics", "low", "A Prometheus metrics endpoint is public", _text_has("# help", "# type")),
]

# Admin / debug endpoints the deep sweep checks for existence (200 + looks real).
ADMIN_PATHS = [
    ("/admin", "medium", "An /admin page is reachable without a login wall"),
    ("/admin/", "medium", "An /admin page is reachable without a login wall"),
    ("/administrator", "medium", "An admin page is reachable"),
    ("/wp-admin/", "medium", "A WordPress admin page is reachable"),
    ("/phpmyadmin/", "high", "phpMyAdmin is reachable"),
    ("/.git/", "high", "The .git folder is browsable"),
    ("/debug", "medium", "A /debug page is reachable"),
    ("/__debug__/", "high", "A debug toolbar endpoint is reachable"),
]

# Where in the CODE this kind of problem usually comes from (best-effort hints).
LOCATE = {
    "static": r"StaticFiles\(|express\.static\(|send_from_directory\(|serve_static|SimpleHTTPRequestHandler|http\.server",
    "cors": r"allow_origins\s*=|CORS\(|(?<![\w.])cors\(|Access-Control-Allow-Origin",
    "app": r"FastAPI\(|Flask\(\s*__name__|express\(\)|createServer\(",
    "debug": r"debug\s*=\s*True|DEBUG\s*=\s*True|app\.run\(",
    "cookie": r"set_cookie\(|res\.cookie\(|SESSION_COOKIE|cookie-session|express-session",
    "route": r"@app\.(get|post|route)\(|app\.(get|post|use)\(|add_url_rule\(",
}


def locate(root, key):
    if not root or not os.path.isdir(root):
        return "", 0
    regex = re.compile(LOCATE[key])
    for path in iter_files(root):
        if os.path.splitext(path)[1].lower() not in {".py", ".js", ".mjs", ".cjs", ".ts"}:
            continue
        text = read_text(path)
        if not text:
            continue
        for n, line in enumerate(text.splitlines(), 1):
            if regex.search(line):
                return rel(path, root), n
    return "", 0


def _add(findings, root, key, **kw):
    f = Finding(category="live", **kw)
    if key:
        file, line = locate(root, key)
        if file:
            f.file, f.line = file, line
            f.why += " (Code location is a best guess - verify it.)"
    findings.append(f)


class _Pacer:
    """Spreads a known number of requests over a target time so the sweep is thorough, not a flood."""
    def __init__(self, planned, target_seconds, enabled):
        self.enabled = enabled
        self.started = time.time()
        gap = (target_seconds / planned) if (enabled and planned > 0) else 0
        self.gap = min(1.2, max(0.15, gap))

    def wait(self):
        if self.enabled and self.gap:
            time.sleep(self.gap)

    def floor(self, min_seconds):
        if not self.enabled:
            return
        left = min_seconds - (time.time() - self.started)
        if left > 0:
            time.sleep(min(left, 30))


def _same_origin_links(base, body):
    """Pull a few same-origin links and ?param= URLs out of a page, for a shallow crawl."""
    links, params = set(), set()
    for m in re.finditer(r'(?:href|action|src)\s*=\s*["\']([^"\'#]+)', body, re.I):
        u = m.group(1).strip()
        if u.startswith(("http://", "https://")):
            if not u.startswith(base):
                continue
            u = u[len(base):]
        if u.startswith(("//", "mailto:", "javascript:", "data:", "tel:")):
            continue
        if not u.startswith("/"):
            u = "/" + u
        (params if "?" in u and "=" in u else links).add(u)
        if "?" in u and "=" in u:
            links.add(u)
    return list(links)[:25], list(params)[:12]


SQL_ERRORS = re.compile(
    r"SQL syntax|SQLITE_ERROR|sqlite3\.|psycopg2|OperationalError|ProgrammingError|"
    r"you have an error in your sql|unclosed quotation mark|ORA-\d{5}|pg_query|mysqli?_",
    re.I)
CANARY = "cbR3FL8"  # harmless reflection marker; the angle-bracket probe below adds <> to test escaping


def _run_probes(findings, code_root, base, probes, pacer, progress, baseline):
    seen = set()
    for path, sev, title, ok in probes:
        if path in seen:
            continue
        seen.add(path)
        pacer.wait()
        if progress:
            progress(path)
        r = fetch(base + path)
        if not r or r[0] != 200:
            continue
        body = r[2]
        if baseline and body and body == baseline:  # same as the generic "not found" page -> not real
            continue
        try:
            good = ok(body, r[1])
        except Exception:
            good = False
        if not good:
            continue
        _add(findings, code_root, "static", rule="exposed-file", severity=sev,
             title=title + " (%s)" % path,
             why="Anyone who visits %s%s can download it." % (base, path),
             fix="Stop serving that path: serve only a dedicated public/ folder, never the project root. "
                 "Then rotate any secret that was inside.")


def run_live(target_url, code_root=None, deep=False, progress=None):
    """Run the consent-based localhost check.

    deep=False : ~25 requests, fast (hook / CI / scoreboard).
    deep=True  : a slow, thorough 2-3 minute sweep.
    progress   : optional callable(str) for a status line.
    """
    base = validate_target(target_url)
    findings = []
    root = fetch(base + "/")
    if root is None:
        return findings, "Could not connect to %s. Is your app running?" % base
    status, h, body, raw = root

    # A baseline "this path does not exist" response, so we don't flag an SPA that 200s everything.
    baseline = None
    nf = fetch(base + "/cipherbloom-%s-does-not-exist" % CANARY)
    if nf and nf[0] == 200:
        baseline = nf[2]

    probes = NORMAL_PROBES + DEEP_PROBES if deep else NORMAL_PROBES
    crawl_links, crawl_params = ([], [])
    if deep:
        crawl_links, crawl_params = _same_origin_links(base, body)
    planned = len(probes) + len(ADMIN_PATHS) + len(crawl_links) + len(crawl_params) + 12
    pacer = _Pacer(planned, DEEP_TARGET_SECONDS, deep)

    # 1) sensitive files
    _run_probes(findings, code_root, base, probes, pacer, progress, baseline)

    # 2) admin / debug endpoints (deep only)
    if deep:
        for path, sev, title in ADMIN_PATHS:
            pacer.wait()
            if progress:
                progress(path)
            r = fetch(base + path)
            if r and r[0] == 200 and r[2] and r[2] != baseline and "html" in r[1].get("content-type", "").lower():
                _add(findings, code_root, "route", rule="exposed-admin", severity=sev,
                     title=title + " (%s)" % path,
                     why="This page answers without asking who you are. If it does anything sensitive, anyone can reach it.",
                     fix="Put it behind a login check, or bind admin tools to a private network only.")

    # 3) security headers (deep checks the full modern set)
    header_checks = [("x-content-type-options", "X-Content-Type-Options: nosniff"),
                     ("content-security-policy", "Content-Security-Policy")]
    if deep:
        header_checks += [("strict-transport-security", "Strict-Transport-Security (HSTS)"),
                          ("referrer-policy", "Referrer-Policy"),
                          ("permissions-policy", "Permissions-Policy")]
    missing = [label for n, label in header_checks if n not in h]
    if "x-frame-options" not in h and "frame-ancestors" not in h.get("content-security-policy", ""):
        missing.append("X-Frame-Options: DENY")
    if missing:
        _add(findings, code_root, "app", rule="missing-security-headers", severity="low",
             title="Missing security headers: " + ", ".join(missing),
             why="Browsers have built-in protections (clickjacking, MIME sniffing, script injection) that these headers switch on.",
             fix="Add them in one place (Express: `helmet()`; FastAPI/Flask: a small middleware or `flask-talisman`).")

    for leak in ("server", "x-powered-by"):
        if leak in h and re.search(r"\d", h[leak]):
            _add(findings, code_root, "app", rule="version-disclosure", severity="low",
                 title="Server reveals its version (%s: %s)" % (leak, h[leak]),
                 why="Attackers search for known bugs in exactly that version.",
                 fix="Hide it (Express: `app.disable('x-powered-by')`; uvicorn: `--no-server-header`).")

    # 4) CORS
    evil = "https://cipherbloom-test.invalid"
    pacer.wait()
    c = fetch(base + "/", headers={"Origin": evil})
    if c:
        acao = c[1].get("access-control-allow-origin", "")
        creds = c[1].get("access-control-allow-credentials", "").lower() == "true"
        if acao == evil and creds:
            _add(findings, code_root, "cors", rule="cors-reflect-credentials", severity="high",
                 title="CORS trusts ANY website and allows cookies",
                 why="A malicious site can make a visitor's browser call your API with their login.",
                 fix="Replace the reflected origin with a fixed allow-list of your own domains.")
        elif acao in ("*", evil):
            _add(findings, code_root, "cors", rule="cors-wildcard", severity="medium",
                 title="CORS allows every website (Access-Control-Allow-Origin: %s)" % acao,
                 why="Any website can read responses from your API in a visitor's browser.",
                 fix="Allow only the exact origins you control, e.g. https://yourapp.com.")

    # 5) dangerous HTTP methods (deep only, via a read-only OPTIONS request)
    if deep:
        pacer.wait()
        if progress:
            progress("OPTIONS /")
        opt = fetch(base + "/", method="OPTIONS")
        allow = (opt[1].get("allow", "") if opt else "").upper()
        risky = [m for m in ("PUT", "DELETE", "TRACE", "PATCH", "CONNECT") if m in allow]
        if risky:
            _add(findings, code_root, "app", rule="risky-http-methods", severity="medium",
                 title="Server advertises risky HTTP methods: " + ", ".join(risky),
                 why="Methods like PUT/DELETE/TRACE can let clients change files or echo back headers if left on by mistake.",
                 fix="Allow only the methods each route needs (usually GET/POST) and turn TRACE off.")

    # 6) debug pages / stack traces / interactive console
    err = fetch(base + "/__cipherbloom_probe_404__")
    if err and re.search(r"Traceback \(most recent call last\)|Werkzeug Debugger|Whoops!|at Object\.<anonymous>|node_modules/", err[2]):
        _add(findings, code_root, "debug", rule="debug-page", severity="high",
             title="Error pages show internal stack traces (debug mode is on)",
             why="Stack traces reveal file paths and code, and some debug pages let visitors run code.",
             fix="Turn debug off outside development and return a plain 500/404 page.")
    for cpath in (("/console", "/__debug__/console") if deep else ("/console",)):
        pacer.wait()
        cons = fetch(base + cpath)
        if cons and cons[0] == 200 and re.search(r"Interactive Console|Werkzeug|console_init", cons[2], re.I):
            _add(findings, code_root, "debug", rule="werkzeug-console", severity="critical",
                 title="Interactive debug console is exposed at %s" % cpath,
                 why="Anyone who reaches it can run code on your machine.",
                 fix="Set debug=False and never expose a debug server.")
            break

    # 7) directory listing (home page + a few common folders in deep mode)
    def _is_listing(text):
        return bool(re.search(r"<title>Index of /|Directory listing for ", text))
    if _is_listing(body):
        _add(findings, code_root, "static", rule="directory-listing", severity="medium",
             title="Directory listing is enabled",
             why="Visitors can browse your files like a folder.",
             fix="Serve a specific folder with listing disabled, or add an index.html.")
    if deep:
        for folder in ("/static/", "/uploads/", "/media/", "/files/", "/assets/", "/backup/", "/.git/"):
            pacer.wait()
            r = fetch(base + folder)
            if r and r[0] == 200 and _is_listing(r[2]):
                _add(findings, code_root, "static", rule="directory-listing", severity="medium",
                     title="Directory listing is enabled at %s" % folder,
                     why="Visitors can browse every file in that folder.",
                     fix="Disable auto-indexing for that folder or add an index file.")

    # 8) cookie flags
    cookies = raw.get_all("Set-Cookie") or []
    for ck in cookies:
        low = ck.lower()
        miss = [n for n, t in (("HttpOnly", "httponly"), ("SameSite", "samesite")) if t not in low]
        if miss:
            _add(findings, code_root, "cookie", rule="weak-cookie", severity="low",
                 title="Cookie '%s' is missing %s" % (ck.split("=", 1)[0], ", ".join(miss)),
                 why="Scripts on the page can read it, or other sites can send it along with their requests.",
                 fix="Set HttpOnly, SameSite=Lax (or Strict), and Secure when you use HTTPS.")

    # 9) public API docs
    for p, title in (("/docs", "API docs"), ("/openapi.json", "OpenAPI schema"), ("/swagger", "Swagger UI"),
                     ("/redoc", "ReDoc API docs"), ("/graphql", "GraphQL endpoint")):
        pacer.wait()
        r = fetch(base + p)
        if r and r[0] == 200 and ("swagger" in r[2].lower() or "openapi" in r[2].lower()
                                  or "redoc" in r[2].lower() or (p == "/graphql" and "graphql" in r[2].lower())):
            findings.append(Finding(
                rule="api-docs-public", severity="info", category="live",
                title="%s is public at %s" % (title, p),
                why="Fine while developing. In production it shows attackers every endpoint you have.",
                fix="Disable or protect it in production (FastAPI: FastAPI(docs_url=None, openapi_url=None))."))
            break

    # 10) reflection + SQL-error canaries on your own ?param= URLs (deep only, read-only markers)
    if deep:
        tested_reflect = tested_sql = False
        for link in crawl_params:
            if tested_reflect and tested_sql:
                break
            parsed = urllib.parse.urlparse(link)
            q = urllib.parse.parse_qsl(parsed.query)
            if not q:
                continue
            # reflection canary: a marker wrapped in angle brackets; if it comes back unescaped
            # in an HTML page, the page is injectable. The marker does nothing on its own.
            if not tested_reflect:
                probe = "%s<%s>" % (CANARY, CANARY)
                nq = [(k, probe) for k, _ in q]
                url = base + parsed.path + "?" + urllib.parse.urlencode(nq)
                pacer.wait()
                if progress:
                    progress(parsed.path + " (reflection)")
                r = fetch(url)
                if r and "html" in r[1].get("content-type", "").lower() and probe in r[2]:
                    tested_reflect = True
                    _add(findings, code_root, "route", rule="reflected-input", severity="high",
                         title="Input is reflected onto the page unescaped (%s)" % parsed.path,
                         why="A marker with < > came back exactly as sent, so a real script tag would run too (reflected XSS).",
                         fix="HTML-escape every value you put into a page, or use your framework's auto-escaping templates.")
            # SQL-error canary: a single quote. Non-destructive; we only read the error text back.
            if not tested_sql:
                nq = [(k, (v + "'") if v else "1'") for k, v in q]
                url = base + parsed.path + "?" + urllib.parse.urlencode(nq)
                pacer.wait()
                if progress:
                    progress(parsed.path + " (sql canary)")
                r = fetch(url)
                if r and SQL_ERRORS.search(r[2]):
                    tested_sql = True
                    _add(findings, code_root, "route", rule="sql-error-leak", severity="high",
                         title="A database error leaks from a URL parameter (%s)" % parsed.path,
                         why="Adding a single quote produced a raw SQL error, a classic sign the query is built by string-joining user input (SQL injection).",
                         fix="Use parameterised queries / an ORM; never build SQL by concatenating request values.")

    pacer.floor(DEEP_MIN_SECONDS)
    return findings, ""
