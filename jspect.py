#!/usr/bin/env python3
"""
jspect.py — Automated JavaScript analysis pipeline for web app pentesting.

Two operating modes:
  URL mode  (-u)    Crawl a live target, download its JS, then analyse it.
  Dir mode  (--dir) Analyse a local source tree directly (skips crawl/download).
  Combined          --dir + -u  gives full static analysis AND live endpoint probing.

Pipeline stages:
  1    Katana crawl                  — discover JS URLs (URL mode only)
  2    JS download                   — fetch and deduplicate JS files (URL mode only)
  2b   Multi-level JS discovery      — follow JS-referenced JS imports (URL mode only)
  2c   Beautification                — expand minified JS for readability
  3    Source-map recovery           — unpack webpack source maps when present (URL mode only)
  4    JSluice                       — AST-based endpoint + secret extraction
  4b   Active recon                  — Google dorks + broad Wayback CDX (opt-in)
  4c   Well-known files              — robots/sitemap/.well-known/leaks probe
  5    Live endpoint validation      — HTTP probe all discovered endpoints
  5b   Static metadata analysis      — source maps, JSON files, developer comments
  5c   HTTP call + secret extraction — fetch/axios/XHR/Express routes, JWT/AWS/key patterns
  5d   Wayback maps                  — historically captured .js.map files (CDX API)
  6    Semgrep SAST                  — DOM sinks, eval, open redirect, cookie misconfig
  7    Retire.js                     — known-vulnerable library fingerprinting
  8    TruffleHog                    — secret/credential detection
  9    HTML report                   — dark-themed, collapsible, self-contained

Usage:
  ./jspect.py -u https://target.com
  ./jspect.py -u https://target.com -H "Cookie: session=abc123"
  ./jspect.py -u https://target.com -H "Authorization: Bearer eyJ..." -d 6
  ./jspect.py -u https://target.com --verify-secrets       # ROE permitting
  ./jspect.py --dir /path/to/NodeGoat                      # local source analysis
  ./jspect.py --dir /path/to/NodeGoat -u http://localhost:4000  # combined
"""

import argparse
import json
import math
import os
import platform
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
import urllib.parse


def _in_docker() -> bool:
    """Return True when running inside a Docker container."""
    return Path("/.dockerenv").exists() or os.environ.get("JSPECT_DOCKER") == "1"

# Evaluated once at import time — avoids repeated filesystem stat calls.
_IN_DOCKER: bool = _in_docker()


# ---------- Pipeline constants ----------
# Centralised here so they are easy to tune without hunting through the code.

# Katana
KATANA_CONCURRENCY       = 10    # parallel browser tabs
KATANA_MFC               = 30    # max consecutive failures before aborting crawl
KATANA_TIMEOUT_BUFFER    = 60    # extra seconds beyond --max-duration for the process timeout
KATANA_LOW_URL_THRESHOLD = 20    # warn when fewer URLs than this are discovered

# HTTP fetch (downloading JS, probing endpoints)
FETCH_JS_TIMEOUT         = 20    # seconds per JS file download
FETCH_GENERIC_TIMEOUT    = 15    # seconds for generic HTTP probes
ENDPOINT_CHECK_TIMEOUT   = 10    # seconds per live-endpoint probe
THREAD_POOL_WORKERS      = 10    # concurrent workers for JS download + endpoint probing

# Minification detection heuristics
MINIFIED_AVG_LINE_LEN    = 200   # avg chars/line above which a file is considered minified
MINIFIED_MAX_LINE_LEN    = 5000  # any line longer than this → definitely minified

# JSluice
JSLUICE_BATCH_SIZE       = 500   # max files per jsluice invocation
JSLUICE_TIMEOUT          = 300   # seconds for the jsluice subprocess

# Semgrep
SEMGREP_RULE_TIMEOUT     = 60    # seconds per rule before semgrep skips it
SEMGREP_TIMEOUT_THRESHOLD = 10   # max rule timeouts per file before semgrep skips the file
SEMGREP_OVERALL_TIMEOUT  = 900   # seconds for the whole semgrep run (15 min)

# Retire.js
RETIRE_TIMEOUT           = 180   # seconds

# TruffleHog
TRUFFLEHOG_TIMEOUT       = 300   # seconds

# Live endpoint validation
MAX_ENDPOINTS_TO_VALIDATE = 500  # cap to avoid probing thousands of generated URLs

# Source-map tooling
UNWEBPACK_TIMEOUT        = 60    # seconds for unwebpack
SOURCEMAPPER_TIMEOUT     = 300   # seconds for sourcemapper


# ---------- Banner + colors ----------

class C:
    """ANSI colors — only active if stdout is a TTY."""
    if sys.stdout.isatty():
        GREEN = "\033[32m"
        RED = "\033[31m"
        YELLOW = "\033[33m"
        BLUE = "\033[34m"
        CYAN = "\033[36m"
        MAGENTA = "\033[35m"
        BOLD = "\033[1m"
        DIM = "\033[2m"
        RESET = "\033[0m"
    else:
        GREEN = RED = YELLOW = BLUE = CYAN = MAGENTA = BOLD = DIM = RESET = ""


BANNER = rf"""{C.CYAN}{C.BOLD}
   _                 _
  (_)____ __  ___ __| |_
  | (_-< '_ \/ -_) _|  _|
 _/ /__/ .__/\___\__|\__|
|__/   |_|                {C.RESET}{C.DIM}v1.0{C.RESET}
{C.DIM}     Automated JavaScript Analysis Pipeline
     Katana → JSluice → Semgrep → TruffleHog{C.RESET}
"""


def print_banner():
    print(BANNER)


# ---------- Logging ----------

class Log:
    """Simple level-based logger. Levels: 0=quiet, 1=normal (default), 2=verbose, 3=debug."""
    level = 1

    @classmethod
    def set_level(cls, level):
        cls.level = level

    @classmethod
    def info(cls, msg):
        """Always shown unless quiet."""
        if cls.level >= 1:
            print(msg)

    @classmethod
    def verbose(cls, msg):
        """Shown at -v and above. Use for stage details, command lines, file counts."""
        if cls.level >= 2:
            print(f"{C.DIM}    [v] {msg}{C.RESET}")

    @classmethod
    def debug(cls, msg):
        """Shown at -vv. Use for per-item details, retry info, raw output snippets."""
        if cls.level >= 3:
            print(f"{C.DIM}    [d] {msg}{C.RESET}")

    @classmethod
    def warn(cls, msg):
        if cls.level >= 1:
            print(f"    {C.YELLOW}[!]{C.RESET} {msg}")

    @classmethod
    def error(cls, msg):
        print(f"    {C.RED}[✗]{C.RESET} {msg}", file=sys.stderr)


def stage_header(num, name):
    """Print a uniform stage header."""
    Log.info(f"\n{C.BOLD}[*] Stage {num} — {name}{C.RESET}")


def platform_info():
    """Return a human-readable platform string for verbose mode."""
    import platform
    return f"{platform.system()} {platform.release()} ({platform.machine()}), Python {platform.python_version()}"


# ---------- Tool checks ----------

REQUIRED_TOOLS = {
    "katana": ("Web crawler / JS endpoint extraction",
               "go install github.com/projectdiscovery/katana/cmd/katana@latest"),
    "jsluice": ("AST-based endpoint + secret extraction",
                "go install github.com/BishopFox/jsluice/cmd/jsluice@latest"),
    "semgrep": ("JS SAST / DOM sink discovery",
                "pip install semgrep"),
    "trufflehog": ("Verified secret detection",
                   "curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin"),
    "retire": ("Known-vulnerable JS library detection",
               "npm install -g retire"),
}

OPTIONAL_TOOLS = {
    "unwebpack-sourcemap": ("Source map recovery — fallback (skipped if missing)",
                            "pipx install unwebpack-sourcemap --python python3.11"),
    "mapperplus": ("Source map recovery — preferred, uses headless browser",
                   "git clone https://github.com/midoxnet/mapperplus && cd mapperplus && bash requirements.sh"),
    "sourcemapper": ("Required by mapperplus to extract sources from .map files",
                     "go install github.com/denandz/sourcemapper@latest"),
}


# Extra search paths for tools that live outside the system PATH.
# Checked in order after shutil.which() fails.
_EXTRA_SEARCH_PATHS: list[Path] = [
    Path.home() / "go" / "bin",          # default GOPATH/bin on macOS/Linux
    *(                                    # $GOPATH/bin if GOPATH env var is set
        [Path(os.environ["GOPATH"]) / "bin"]
        if os.environ.get("GOPATH") else []
    ),
    Path("/usr/local/go/bin"),
    Path("/opt/homebrew/bin"),
]

# Script-based tools: name → (interpreter, relative path from this script's directory).
# When the "binary" is actually a Python/Node script that was cloned locally, we detect
# the script file and record the interpreter+path so run() can invoke it correctly.
_THIS_DIR = Path(__file__).resolve().parent
_SCRIPT_TOOLS: dict[str, tuple[str, Path]] = {
    "mapperplus": ("python3", _THIS_DIR / "mapperplus" / "mapperplus.py"),
}

# Resolved paths — populated by find_tool(), used by callers via tool_cmd().
_TOOL_PATHS: dict[str, list[str]] = {}


def find_tool(name: str) -> bool:
    """
    Return True if the tool is available; populate _TOOL_PATHS with the full
    command list to invoke it (e.g. ["python3", "/path/to/mapperplus.py"]).

    Search order:
      1. Script-based tools (cloned repos with a Python/Node entry point).
      2. shutil.which() — standard PATH lookup.
      3. _EXTRA_SEARCH_PATHS — common Go/Homebrew bin directories not always in PATH.
    """
    # 1. Script-based tool
    if name in _SCRIPT_TOOLS:
        interp, script_path = _SCRIPT_TOOLS[name]
        if script_path.is_file():
            _TOOL_PATHS[name] = [interp, str(script_path)]
            return True
        return False

    # 2. Standard PATH
    found = shutil.which(name)
    if found:
        _TOOL_PATHS[name] = [found]
        return True

    # 3. Extra search paths
    for base in _EXTRA_SEARCH_PATHS:
        candidate = base / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            _TOOL_PATHS[name] = [str(candidate)]
            return True

    return False


def tool_cmd(name: str) -> list[str]:
    """Return the resolved command list for a tool (populated by find_tool)."""
    return _TOOL_PATHS.get(name, [name])


def check_environment():
    """Print tool status and exit if any required tool is missing."""
    print(f"{C.BOLD}Environment check{C.RESET}")
    print(f"{C.DIM}{'─' * 60}{C.RESET}")

    missing = []
    available = {}

    print(f"{C.BOLD}Required:{C.RESET}")
    for tool, (purpose, install_cmd) in REQUIRED_TOOLS.items():
        present = find_tool(tool)
        available[tool] = present
        if present:
            cmd_hint = " ".join(tool_cmd(tool)) if tool in _TOOL_PATHS else tool
            print(f"  {C.GREEN}✓{C.RESET} {tool:25} {C.DIM}— {purpose}{C.RESET}")
            if cmd_hint != tool:
                print(f"    {C.DIM}→ {cmd_hint}{C.RESET}")
        else:
            print(f"  {C.RED}✗{C.RESET} {tool:25} {C.DIM}— {purpose}{C.RESET}")
            print(f"    {C.DIM}install: {install_cmd}{C.RESET}")
            missing.append(tool)

    print(f"{C.BOLD}Optional:{C.RESET}")
    for tool, (purpose, install_cmd) in OPTIONAL_TOOLS.items():
        present = find_tool(tool)
        available[tool] = present
        if present:
            cmd_hint = " ".join(tool_cmd(tool)) if tool in _TOOL_PATHS else tool
            print(f"  {C.GREEN}✓{C.RESET} {tool:25} {C.DIM}— {purpose}{C.RESET}")
            if cmd_hint != tool:
                print(f"    {C.DIM}→ {cmd_hint}{C.RESET}")
        else:
            print(f"  {C.YELLOW}○{C.RESET} {tool:25} {C.DIM}— {purpose}{C.RESET}")
            print(f"    {C.DIM}install: {install_cmd}{C.RESET}")

    print(f"{C.DIM}{'─' * 60}{C.RESET}\n")

    if missing:
        print(f"{C.RED}{C.BOLD}[!] Missing required tools: {', '.join(missing)} — cannot proceed.{C.RESET}\n")
        sys.exit(1)

    return available


# ---------- Scope + redirect helpers ----------

# Common open-redirect parameter names
REDIRECT_PARAMS = {
    "to", "url", "redirect", "redirect_uri", "redirecturi", "redir",
    "next", "return", "returnurl", "return_to", "returnto",
    "dest", "destination", "goto", "continue", "forward",
    "out", "target", "rurl", "go", "site", "u", "link",
    "callback", "checkout_url",
}


def is_in_scope(url, target_host):
    """True if URL is in scope (same host or any relative reference)."""
    if not url:
        return False
    url = url.strip()
    # Absolute URL with scheme — check hostname
    if url.startswith(("http://", "https://")):
        try:
            parsed = urlparse(url).hostname
            if not parsed or not target_host:
                return False
            return parsed == target_host or parsed.endswith("." + target_host)
        except Exception:
            return False
    # Protocol-relative URL (//other.com/foo) — check hostname
    if url.startswith("//"):
        try:
            parsed = urlparse("https:" + url).hostname
            return bool(parsed) and (parsed == target_host or parsed.endswith("." + target_host))
        except Exception:
            return False
    # Skip obvious non-URL strings (mime types, scheme-only fragments, etc.)
    if url.startswith(("data:", "javascript:", "mailto:", "tel:", "blob:", "about:")):
        return False
    # Anything else — assume in-scope (relative paths, filenames, etc.)
    return True


def looks_like_api(url):
    """True if URL path looks like an API route."""
    if not url:
        return False
    return any(p in url for p in [
        "/api/", "/rest/", "/v1/", "/v2/", "/v3/", "/v4/",
        "/graphql", "/gql", "/jsonrpc", "/rpc/",
    ])


# ---------- Shared HTTP / I/O helpers ----------

def parse_headers(headers):
    """Parse a list of 'Name: value' header strings into a dict.
    Always returns a dict with at least a User-Agent header set.
    """
    out = {}
    for h in headers or []:
        if ":" in h:
            k, v = h.split(":", 1)
            out[k.strip()] = v.strip()
    out.setdefault("User-Agent", "Mozilla/5.0 jspect/1.0")
    return out


def permissive_ssl_context():
    """SSL context that accepts self-signed certs common on UAT/dev targets."""
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def fetch_url(url, headers=None, timeout=15, max_bytes=None):
    """Fetch a URL with parsed headers and permissive SSL.

    Returns (status, body_text) where:
      - status is the HTTP code, or None on connection error
      - body_text is the decoded response body (empty string on any failure)

    Errors are caught and logged at debug level — never raised.
    """
    import urllib.request
    import urllib.error
    try:
        req = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(req, context=permissive_ssl_context(), timeout=timeout) as resp:
            content = resp.read(max_bytes) if max_bytes else resp.read()
            return resp.status, content.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception as e:
        Log.debug(f"fetch_url({url[:80]}) failed: {type(e).__name__}: {str(e)[:80]}")
        return None, ""


def count_nonempty_lines(path):
    """Count non-empty lines in a file. Returns 0 on any error."""
    if not path or not Path(path).exists():
        return 0
    try:
        with Path(path).open(encoding="utf-8", errors="replace") as f:
            return sum(1 for line in f if line.strip())
    except OSError:
        return 0


def host_in_scope(url, target_host):
    """True if URL's host matches target_host or is a subdomain of it."""
    if not url or not target_host:
        return False
    try:
        if url.startswith(("http://", "https://")):
            h = urlparse(url).hostname
        elif url.startswith("//"):
            h = urlparse("https:" + url).hostname
        else:
            return False
    except Exception:
        return False
    if not h:
        return False
    return h == target_host or h.endswith("." + target_host)


def is_open_redirect_candidate(endpoint):
    """True if endpoint has a known redirect-style query parameter."""
    url = (endpoint.get("url") or "").lower()
    params = [p.lower() for p in (endpoint.get("queryParams") or [])]
    if any(p in REDIRECT_PARAMS for p in params):
        return True
    # Also check the URL itself for ?param= patterns (some JSluice rows
    # capture the param in the URL but leave queryParams empty)
    for param in REDIRECT_PARAMS:
        if f"?{param}=" in url or f"&{param}=" in url:
            return True
    return False


# ---------- Subprocess helper ----------

def run(cmd, cwd=None, check=True, capture=False, quiet=False, timeout=None):
    cmd_str = ' '.join(cmd) if isinstance(cmd, list) else cmd
    if not quiet:
        Log.verbose(f"$ {cmd_str}")
    if timeout:
        Log.debug(f"timeout={timeout}s, cwd={cwd or 'cwd'}")
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            check=check,
            shell=isinstance(cmd, str),
            capture_output=capture,
            text=True,
            timeout=timeout,
        )
        Log.debug(f"exit={result.returncode}")
        return result
    except subprocess.TimeoutExpired:
        Log.warn(f"command timed out after {timeout}s: {cmd_str[:80]}")
        return None
    except subprocess.CalledProcessError as e:
        Log.warn(f"command failed (exit {e.returncode}): {cmd_str[:80]}")
        if capture and e.stderr:
            Log.debug(f"stderr: {e.stderr[:300]}")
        if check:
            raise
        return e


# ---------- Stage 1: Katana ----------

def run_katana(target, output_dir, headers, depth, rate_limit, headless, max_duration,
               proxy=None):
    stage_header(1, "Katana crawl")
    out_txt = output_dir / "katana-out.txt"
    # Persist the seed URL so downstream stages can fall back to the homepage
    # when Katana yields nothing (UA blocks, JS-only landers, geo blocks, …).
    (output_dir / "katana-target.txt").write_text(target, encoding="utf-8")

    cmd = [
        "katana",
        "-u", target,
        "-jc",
        "-jsl",
        "-kf", "all",
        "-aff",
        "-fx",
        "-d", str(depth),
        "-c", str(KATANA_CONCURRENCY),
        "-p", "5",
        "-rl", str(rate_limit),
        "-ct", str(max_duration),
        "-mfc", str(KATANA_MFC),   # raise failure ceiling; Angular {{template}} 404s quickly exhaust the default of 10
        "-o", str(out_txt),
        "-silent",
    ]

    # Scope to the target's host so we don't wander
    host = urlparse(target).hostname or ""
    if host:
        host_re = host.replace(".", r"\.")
        cmd.extend(["-cs", host_re])
        Log.verbose(f"scope regex: {host_re}")

    if headless:
        chrome_opts = "--headless=new,--disable-blink-features=AutomationControlled"
        if _IN_DOCKER:
            # Chrome's sandbox requires Linux namespaces that are typically
            # unavailable in Docker containers. Disable it inside the image.
            chrome_opts += ",--no-sandbox,--disable-dev-shm-usage"
            Log.verbose("Docker detected — adding --no-sandbox to Chrome flags")
        cmd.extend([
            "-headless",
            "-system-chrome",
            "-headless-options", chrome_opts,
        ])
        Log.verbose("running headless with system Chrome")
    else:
        Log.verbose("running with visible browser")

    for h in headers:
        cmd.extend(["-H", h])
    if headers:
        Log.verbose(f"using {len(headers)} auth header(s)")

    # Katana ignores HTTP(S)_PROXY env vars — it only honors its own -proxy flag.
    if proxy:
        cmd.extend(["-proxy", proxy])
        Log.verbose(f"routing Katana through proxy: {proxy}")

    Log.verbose(f"depth={depth}, rate-limit={rate_limit}/s, max-duration={max_duration}min")

    # Hard timeout = crawl duration + buffer to let katana flush output
    run(cmd, check=False, timeout=max_duration * 60 + KATANA_TIMEOUT_BUFFER)

    if not out_txt.exists() or out_txt.stat().st_size == 0:
        Log.warn("Katana produced no output. Check auth/target reachability.")
        return None, None

    url_count = count_nonempty_lines(out_txt)
    Log.info(f"    {C.GREEN}[+]{C.RESET} {url_count} URLs found")
    if url_count < KATANA_LOW_URL_THRESHOLD:
        Log.info(f"    {C.DIM}↳ Low URL count — check auth, increase -d, or the app may be small{C.RESET}")
    return out_txt, url_count


# ---------- Stage 2: Download JS ----------

# Match <script src="…"> / <script type="module" src="…"> / <link rel="modulepreload" href="…">
# / <link rel="preload" as="script" href="…">  — case-insensitive, attribute order agnostic.
_HTML_JS_REFS = [
    re.compile(r'<script\b[^>]*\bsrc\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'<link\b[^>]*\brel\s*=\s*["\']modulepreload["\'][^>]*\bhref\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'<link\b[^>]*\bhref\s*=\s*["\']([^"\']+)["\'][^>]*\brel\s*=\s*["\']modulepreload["\']', re.IGNORECASE),
    re.compile(r'<link\b[^>]*\brel\s*=\s*["\']preload["\'][^>]*\bas\s*=\s*["\']script["\'][^>]*\bhref\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE),
]


def _scripts_from_html_pages(page_urls: list[str], headers) -> list[str]:
    """Fetch each URL (text/html), parse <script src=> and <link modulepreload> refs.
    Returns absolute, deduped JS URLs filtered to the same site.
    """
    import html as _html_mod
    if not page_urls:
        return []
    header_dict = parse_headers(headers)
    out: list[str] = []
    seen: set[str] = set()
    # All targets must end up same-host as the very first page URL (the user's -u)
    base_host = urlparse(page_urls[0]).hostname or ""
    base_scheme = urlparse(page_urls[0]).scheme or "https"

    for page_url in page_urls:
        status, body = fetch_url(page_url, headers=header_dict,
                                  timeout=FETCH_GENERIC_TIMEOUT, max_bytes=2_000_000)
        if status != 200 or not body or "<" not in body:
            continue
        # Look only at the <head>... if the doc has one (cheap perf win on huge pages)
        head_match = re.search(r"<head\b[^>]*>(.*?)</head>", body, re.IGNORECASE | re.DOTALL)
        scan_text = head_match.group(1) if head_match else body[:200_000]
        # Plus <body>'s footer scripts — many CMSes load scripts at bottom
        if not head_match or "<script" in body.lower()[len(scan_text):]:
            scan_text = body[:500_000]

        for pat in _HTML_JS_REFS:
            for m in pat.finditer(scan_text):
                ref = _html_mod.unescape(m.group(1)).strip()
                if not ref or ref.startswith(("data:", "blob:", "javascript:", "#")):
                    continue
                # Resolve to absolute URL
                if ref.startswith("//"):
                    url = f"{base_scheme}:{ref}"
                elif ref.startswith("/"):
                    url = f"{base_scheme}://{base_host}{ref}"
                elif ref.startswith(("http://", "https://")):
                    url = ref
                else:
                    # Relative path — resolve against the page URL
                    from urllib.parse import urljoin
                    url = urljoin(page_url, ref)
                # Same-host filter
                u_host = urlparse(url).hostname or ""
                if u_host != base_host and not u_host.endswith("." + base_host):
                    continue
                # Strip the fragment, keep the query (some CMSes use bundlers with ?v=)
                url = url.split("#", 1)[0]
                # Heuristic: must look like a JS resource — by extension or by `*.php?...=*.js`
                base = url.split("?")[0].lower()
                looks_jsy = (base.endswith((".js", ".mjs", ".js.map"))
                             or ".js," in url.lower()
                             or ".js?" in url.lower())
                if not looks_jsy:
                    # Still allow if the URL was harvested from <script src> — server
                    # may serve JS from a routed endpoint (e.g. DLE's min/index.php)
                    if "/min/" in url.lower() or "/javascript/" in url.lower() \
                       or "?charset=" in url.lower():
                        pass
                    else:
                        continue
                if url not in seen:
                    seen.add(url)
                    out.append(url)
    return out


def download_js(katana_out, output_dir, headers):
    """Download all JS URLs found by Katana using urllib (no httpx dependency)."""
    import urllib.request
    import urllib.error
    import ssl
    import hashlib
    from concurrent.futures import ThreadPoolExecutor, as_completed

    stage_header(2, "Downloading JS files")
    js_urls = output_dir / "js-urls.txt"
    js_clean = output_dir / "js-clean"
    js_clean.mkdir(exist_ok=True)

    # Extract JS URLs from Katana output
    with katana_out.open() as f, js_urls.open("w") as out:
        seen = set()
        for line in f:
            url = line.strip()
            if not url or url in seen:
                continue
            # Match .js / .js.map / .mjs with optional query string
            base = url.split("?")[0]
            if base.endswith((".js", ".mjs", ".js.map")) or ".js?" in url:
                if not url.startswith(("http://", "https://")):
                    continue
                seen.add(url)
                out.write(url + "\n")

    url_list = [u.strip() for u in js_urls.open() if u.strip()]

    # Augmentation: parse HTML pages from Katana output for <script src=> and
    # module-preload references. Katana without headless rendering only emits
    # page URLs (not <script src=...> from inside them). Without this, most
    # server-rendered sites (WordPress, CodeIgniter, DLE, FusionCMS, etc.)
    # silently get an empty JS corpus.
    #
    # We always run this when HTML pages outnumber JS URLs by 2× or more —
    # otherwise a single Cloudflare-injected /cdn-cgi/scripts/email-decode.min.js
    # would make us skip the real site's bundles.
    page_urls = [u.strip() for u in katana_out.open()
                 if u.strip().startswith(("http://", "https://"))
                 and not u.strip().split("?")[0].lower().endswith(
                     (".js", ".mjs", ".js.map", ".css", ".png", ".jpg",
                      ".jpeg", ".gif", ".svg", ".webp", ".woff", ".woff2",
                      ".ico", ".pdf", ".zip"))]
    # If Katana found absolutely nothing (UA blocks, JS-only landers, geo blocks,
    # CDN challenges, …), at least try the target's own homepage. It came in via
    # `katana_target_url`, persisted by run_katana for exactly this fallback.
    if not page_urls:
        fb = output_dir / "katana-target.txt"
        if fb.exists():
            seed = fb.read_text(encoding="utf-8", errors="replace").strip()
            if seed.startswith(("http://", "https://")):
                page_urls = [seed]
                Log.info(f"    [i] Katana output empty — fetching target homepage "
                         f"directly as fallback ({seed})")
    should_scrape = (
        not url_list                                              # Katana found 0 JS
        or len(page_urls) >= max(2 * len(url_list), 5)            # JS count looks too low
    )
    if should_scrape and page_urls:
        if not url_list:
            Log.info("    [i] No direct JS URLs from Katana — scraping HTML pages "
                     "for <script src> references")
        else:
            Log.info(f"    [i] Only {len(url_list)} JS URL(s) but {len(page_urls)} HTML "
                     f"page(s) — augmenting via <script src> scrape")
        page_urls = page_urls[:15]   # cap (polite, single-thread)
        harvested = _scripts_from_html_pages(page_urls, headers)
        # Dedupe against what Katana already had
        existing = set(url_list)
        new_only = [u for u in harvested if u not in existing]
        if new_only:
            Log.info(f"    {C.GREEN}[+]{C.RESET} Harvested {len(new_only)} additional JS "
                     f"URL(s) from {len(page_urls)} HTML page(s)")
            with js_urls.open("a") as out:
                for u in new_only:
                    out.write(u + "\n")
            url_list = url_list + new_only

    if not url_list:
        Log.warn("No JS URLs found in Katana output (and HTML fallback found none)")
        return None
    Log.info(f"    {C.GREEN}[+]{C.RESET} {len(url_list)} JS URLs to fetch")

    header_dict = parse_headers(headers)
    ctx = permissive_ssl_context()

    def fetch(url):
        try:
            req = urllib.request.Request(url, headers=header_dict)
            with urllib.request.urlopen(req, context=ctx, timeout=FETCH_JS_TIMEOUT) as resp:
                content = resp.read()
                # Use a stable filename based on URL
                name_hint = Path(urllib.parse.urlparse(url).path).name or "index"
                # Strip query string from name_hint
                name_hint = name_hint.split("?")[0]
                if not name_hint.endswith((".js", ".mjs", ".map")):
                    name_hint = name_hint + ".js"
                # Prefix with a short hash so duplicates don't collide
                h = hashlib.sha1(url.encode()).hexdigest()[:8]
                outpath = js_clean / f"{h}_{name_hint}"
                try:
                    text = content.decode("utf-8", errors="replace")
                except Exception:
                    text = content.decode("latin-1", errors="replace")
                outpath.write_text(text, encoding="utf-8", errors="replace")
                return (url, outpath.name, True, resp.status, len(content))
        except urllib.error.HTTPError as e:
            return (url, None, False, e.code, 0)
        except Exception as e:
            return (url, None, False, str(e)[:60], 0)

    ok = 0
    errors = {}
    url_map: dict[str, str] = {}   # filename → original URL
    with ThreadPoolExecutor(max_workers=THREAD_POOL_WORKERS) as pool:
        futures = {pool.submit(fetch, url): url for url in url_list}
        for fut in as_completed(futures):
            url, fname, success, status, size = fut.result()
            if success:
                ok += 1
                if fname:
                    url_map[fname] = url
            else:
                errors.setdefault(str(status), 0)
                errors[str(status)] += 1

    # Persist so the report generator can link filenames back to their source URLs.
    url_map_path = output_dir / "url-map.json"
    existing = json.loads(url_map_path.read_text()) if url_map_path.exists() else {}
    existing.update(url_map)
    url_map_path.write_text(json.dumps(existing, indent=2))

    Log.info(f"    {C.GREEN}[+]{C.RESET} Downloaded {ok}/{len(url_list)} JS files to {js_clean}")
    if errors:
        err_summary = ", ".join(f"{count}x {code}" for code, count in errors.items())
        Log.info(f"    [-] Failures: {err_summary}")

    if ok == 0:
        return None
    return js_clean


# ---------- Stage 2b: Multi-level JS discovery ----------

JS_URL_RE = re.compile(
    r"""['"`]([^'"`\s<>{}()]+?\.m?js(?:\?[^'"`\s<>]*)?)['"`]""",
    re.IGNORECASE,
)


def discover_nested_js(js_clean, output_dir, headers, target, max_levels=2):
    """
    Scan downloaded JS files for references to other JS files and fetch them.
    Catches lazy-loaded chunks and dynamic imports that Katana misses.
    """
    import urllib.request
    import urllib.error
    import ssl
    import hashlib
    from concurrent.futures import ThreadPoolExecutor, as_completed

    stage_header("2b", "Multi-level JS discovery")

    target_parsed = urlparse(target)
    target_host = target_parsed.hostname or ""
    target_base = f"{target_parsed.scheme}://{target_parsed.netloc}"

    header_dict = parse_headers(headers)
    ctx = permissive_ssl_context()

    # Track URLs already seen (downloaded or attempted)
    seen_urls = set()
    # Seed with what we already have. Stored filenames have a hash prefix
    # (e.g. "abc123_app.js" or "L1_abc123_app.js"); strip it to compare against
    # raw filenames extracted from URLs.
    already_files = set()
    hash_prefix_re = re.compile(r"^(L\d+_)?[0-9a-f]{8}_")
    for f in js_clean.glob("*.js"):
        already_files.add(hash_prefix_re.sub("", f.name))

    dangling = []   # JS URLs that returned 4xx — potential dangling-resource issues
    new_added = 0

    def normalize(ref, source_file=None):
        """Turn a JS reference into an absolute URL. Returns None for unsupported."""
        ref = ref.strip()
        if not ref:
            return None
        # Skip data:, blob:, etc.
        if ref.startswith(("data:", "blob:", "javascript:", "mailto:", "tel:", "about:")):
            return None
        if ref.startswith(("http://", "https://")):
            return ref
        if ref.startswith("//"):
            return f"{target_parsed.scheme}:{ref}"
        if ref.startswith("/"):
            return target_base + ref
        # Relative path — resolve against base. Doesn't have to be perfect, just usable.
        return target_base + "/" + ref.lstrip("./")

    def is_target_host(url):
        try:
            h = urlparse(url).hostname or ""
        except Exception:
            return False
        if not h:
            return False
        return h == target_host or h.endswith("." + target_host)

    def fetch(url):
        try:
            req = urllib.request.Request(url, headers=header_dict)
            with urllib.request.urlopen(req, context=ctx, timeout=FETCH_GENERIC_TIMEOUT) as resp:
                content = resp.read()
                return ("ok", resp.status, content)
        except urllib.error.HTTPError as e:
            return ("http_error", e.code, b"")
        except Exception as e:
            return ("error", str(e)[:60], b"")

    # Crawl level by level
    current_files = list(js_clean.glob("*.js"))
    for level in range(1, max_levels + 1):
        # Extract candidate JS URLs from the current batch
        candidates = set()
        for jsfile in current_files:
            try:
                content = jsfile.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            for m in JS_URL_RE.finditer(content):
                ref = m.group(1)
                norm = normalize(ref, source_file=jsfile.name)
                if not norm or norm in seen_urls:
                    continue
                if not is_target_host(norm):
                    continue  # Stay in scope
                # Skip if filename already in our corpus
                fname = norm.split("?")[0].rsplit("/", 1)[-1]
                if fname in already_files:
                    continue
                candidates.add(norm)
                seen_urls.add(norm)

        if not candidates:
            Log.verbose(f"level {level}: no new JS references found, stopping")
            break

        Log.info(f"    {C.GREEN}[+]{C.RESET} Level {level}: {len(candidates)} new JS reference(s)")

        # Fetch them
        new_files_this_level = []
        nested_url_map: dict[str, str] = {}
        with ThreadPoolExecutor(max_workers=THREAD_POOL_WORKERS) as pool:
            future_map = {pool.submit(fetch, u): u for u in candidates}
            for fut in as_completed(future_map):
                url = future_map[fut]
                status, code, content = fut.result()
                if status == "ok" and content:
                    h = hashlib.sha1(url.encode()).hexdigest()[:8]
                    name_hint = Path(urlparse(url).path).name.split("?")[0] or "index.js"
                    if not name_hint.endswith((".js", ".mjs")):
                        name_hint += ".js"
                    outpath = js_clean / f"L{level}_{h}_{name_hint}"
                    try:
                        text = content.decode("utf-8", errors="replace")
                    except Exception:
                        text = content.decode("latin-1", errors="replace")
                    outpath.write_text(text, encoding="utf-8", errors="replace")
                    new_files_this_level.append(outpath)
                    already_files.add(name_hint)
                    nested_url_map[outpath.name] = url
                    new_added += 1
                elif status == "http_error" and isinstance(code, int) and 400 <= code < 500:
                    # Dangling resource — referenced in JS but doesn't exist
                    dangling.append({"url": url, "status": code})
                    Log.debug(f"dangling: {url} → {code}")

        # Merge into the shared url-map so the report can link back to source URLs.
        if nested_url_map:
            url_map_path = output_dir / "url-map.json"
            existing = json.loads(url_map_path.read_text()) if url_map_path.exists() else {}
            existing.update(nested_url_map)
            url_map_path.write_text(json.dumps(existing, indent=2))

        if not new_files_this_level:
            Log.verbose(f"level {level}: no fetches succeeded, stopping")
            break

        current_files = new_files_this_level  # Next level only parses new files

    # Save dangling-resource findings for the report
    dangling_file = None
    if dangling:
        dangling_file = output_dir / "dangling-js.json"
        with dangling_file.open("w") as f:
            for d in dangling:
                f.write(json.dumps(d) + "\n")
        Log.info(f"    {C.YELLOW}[!]{C.RESET} {len(dangling)} dangling JS reference(s) "
                 f"(404/403) — see dangling-js.json")
        Log.info(f"    {C.DIM}↳ Check if any of these filenames could be uploaded via S3/CDN takeover{C.RESET}")

    if new_added == 0:
        Log.info("    [-] No additional JS files discovered")
    else:
        Log.info(f"    {C.GREEN}[+]{C.RESET} Added {new_added} JS file(s) to corpus via multi-level discovery")

    return dangling_file


# ---------- Stage 2c: Beautify minified JS ----------

def beautify_js(js_clean):
    """
    Beautify minified JS files in place so downstream stages (Semgrep, JSluice,
    Retire.js) produce higher-quality output. Uses jsbeautifier (Python package).

    Heuristic for "minified": average line length > 200 chars OR contains a
    single line longer than 5000 chars. Skips files that already look readable.
    """
    stage_header("2c", "Beautify minified JS")

    try:
        import jsbeautifier
    except ImportError:
        Log.warn("jsbeautifier not installed — skipping beautification")
        Log.info(f"    {C.DIM}install: pip install jsbeautifier{C.RESET}")
        return

    opts = jsbeautifier.default_options()
    opts.indent_size = 2
    opts.preserve_newlines = True
    opts.max_preserve_newlines = 2

    js_files = list(js_clean.glob("*.js"))
    if not js_files:
        Log.info("    [-] No JS files to beautify")
        return

    Log.verbose(f"checking {len(js_files)} JS files for minification")

    beautified = 0
    skipped = 0
    failed = 0

    for jsfile in js_files:
        try:
            content = jsfile.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            Log.debug(f"could not read {jsfile.name}: {e}")
            failed += 1
            continue

        if not content.strip():
            skipped += 1
            continue

        # Heuristic: is this file minified?
        lines = content.split("\n")
        max_line = max((len(line) for line in lines), default=0)
        avg_line = sum(len(line) for line in lines) / max(len(lines), 1)
        is_minified = max_line > MINIFIED_MAX_LINE_LEN or avg_line > MINIFIED_AVG_LINE_LEN

        if not is_minified:
            Log.debug(f"already readable: {jsfile.name} (avg={avg_line:.0f}, max={max_line})")
            skipped += 1
            continue

        try:
            pretty = jsbeautifier.beautify(content, opts)
            jsfile.write_text(pretty, encoding="utf-8", errors="replace")
            beautified += 1
            Log.debug(f"beautified {jsfile.name}: {len(content)} → {len(pretty)} bytes")
        except Exception as e:
            Log.debug(f"beautify failed for {jsfile.name}: {str(e)[:80]}")
            failed += 1

    Log.info(f"    {C.GREEN}[+]{C.RESET} Beautified {beautified} file(s), "
             f"skipped {skipped} (already readable)"
             + (f", {failed} failed" if failed else ""))


# ---------- Source map helpers ----------

def _shannon_entropy(s: str) -> float:
    """Shannon entropy in bits/char. High-entropy strings are likely real secrets."""
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in counts.values())


def _extract_map_sources(map_path: Path, sources_dir: Path) -> tuple[list[str], int]:
    """
    Parse a .map (source map JSON) file and write each sourcesContent entry as a
    separate file under sources_dir.  Returns (source_paths, files_written).

    This is the core value of source map exposure: the original pre-minified source
    code is embedded verbatim in the sourcesContent array — no external tool needed.
    """
    try:
        data = json.loads(map_path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return [], 0

    src_paths: list[str] = data.get("sources", [])
    contents: list[str]  = data.get("sourcesContent", []) or []

    if not contents:
        return src_paths, 0

    sources_dir.mkdir(exist_ok=True)
    prefix = map_path.stem[:10]   # keep path short but identifiable
    # macOS/Linux filename-component limit is 255 bytes. Be conservative —
    # leave room for the `{prefix}__` prefix and any future suffix.
    MAX_NAME_LEN = 200
    written = 0
    for i, content in enumerate(contents):
        if not content:
            continue
        # Derive a readable filename from the source path entry.
        raw = src_paths[i] if i < len(src_paths) else f"source_{i}"
        # Strip webpack:// / file:// prefixes that pollute the path.
        clean = re.sub(r'^(?:webpack://[^/]*/|webpack:///|file://)', "", raw)
        clean = clean.lstrip("./")
        safe  = re.sub(r'[^\w.\-]', '_', clean) or f"source_{i}"

        # Cap super-long names (Nuxt + pnpm produces 500+ char node_modules paths
        # like ".pnpm/@nuxt+icon@2.2.2_magicast@0.5.2_vite@7.3.3_..._lightningcss..."
        # which exceed the OS filename limit and would crash the whole stage).
        # Keep the END of the path (the actual file name is more useful than the
        # dependency-graph prefix) and add a short hash for uniqueness.
        if len(safe) > MAX_NAME_LEN:
            import hashlib as _h
            tail = safe[-(MAX_NAME_LEN - 12):]   # leave room for hash prefix
            digest = _h.sha1(safe.encode("utf-8", errors="replace")).hexdigest()[:8]
            safe = f"{digest}__{tail}"

        dest = sources_dir / f"{prefix}__{safe}"
        try:
            dest.write_text(content, encoding="utf-8", errors="replace")
            written += 1
        except OSError as exc:
            # Path too long, perm denied, disk full etc. — don't kill the whole
            # stage over a single pathological source-map entry.
            Log.debug(f"skipped extracted source (write failed): {exc.__class__.__name__}: {str(exc)[:120]}")
            continue

    return src_paths, written


# ---------- Stage 3: Source map recovery ----------

def recover_source_maps(js_clean, output_dir, available_tools, target, headers):
    """
    Try MapperPlus first (headless-browser based, catches lazy-loaded maps).
    Fall back to local .map files + unwebpack-sourcemap if MapperPlus unavailable.
    """
    stage_header(3, "Source map recovery")

    sources_dir = output_dir / "sources"
    sources_dir.mkdir(exist_ok=True)

    # --- Path 1: MapperPlus (preferred) ---
    if available_tools.get("mapperplus") and available_tools.get("sourcemapper"):
        Log.verbose("using MapperPlus (headless-browser-based)")
        cookies_arg = []
        custom_headers = []
        for h in headers:
            if h.lower().startswith("cookie:"):
                # MapperPlus expects a cookies file
                cookies_file = output_dir / ".mapperplus-cookies.txt"
                cookies_file.write_text(h.split(":", 1)[1].strip() + "\n")
                cookies_arg = ["-c", str(cookies_file)]
            else:
                custom_headers.extend(["-h", h])

        cmd = tool_cmd("mapperplus") + [
            "-u", target,
            "-t", str(sources_dir),
        ] + cookies_arg + custom_headers

        result = run(cmd, check=False, timeout=SOURCEMAPPER_TIMEOUT, capture=True, quiet=True)
        if result and result.returncode == 0:
            # Count what got extracted
            extracted = list(sources_dir.rglob("*"))
            extracted_files = [p for p in extracted if p.is_file()]
            if extracted_files:
                Log.info(f"    {C.GREEN}[+]{C.RESET} MapperPlus extracted {len(extracted_files)} source file(s) to {sources_dir}")
                return sources_dir
            Log.info("    [-] MapperPlus ran but extracted no sources (no .js.map exposed)")
            # fall through to local-file attempt
        else:
            Log.verbose("MapperPlus failed, falling back to local .map files")

    # --- Path 2: Python-native sourcesContent extraction (no external binary needed) ---
    local_maps = list(js_clean.glob("*.map")) + list(js_clean.glob("*.js.map"))
    py_extracted = 0
    for mapfile in local_maps:
        _, written = _extract_map_sources(mapfile, sources_dir)
        py_extracted += written

    if py_extracted:
        Log.info(f"    {C.GREEN}[+]{C.RESET} Extracted {py_extracted} source file(s) from local maps "
                 f"(Python parser) to {sources_dir}")
        return sources_dir

    # --- Path 3: unwebpack-sourcemap binary (kept as extra fallback) ---
    if available_tools.get("unwebpack-sourcemap"):
        unpacked = 0
        for mapfile in local_maps:
            result = run(
                ["unwebpack-sourcemap", "--output-directory", str(sources_dir), str(mapfile)],
                check=False, capture=True, quiet=True, timeout=UNWEBPACK_TIMEOUT
            )
            if result and result.returncode == 0:
                unpacked += 1
        if unpacked:
            Log.info(f"    {C.GREEN}[+]{C.RESET} Unpacked {unpacked} source map(s) via unwebpack-sourcemap")
            return sources_dir

    Log.info("    [-] No local .map files found to extract")
    return None


# ---------- Stage 4: JSluice ----------

def run_jsluice(target_dir, output_dir):
    stage_header(4, "JSluice (endpoints + secrets)")
    endpoints_json = output_dir / "endpoints.json"
    secrets_json = output_dir / "secrets.json"

    # rglob already covers everything — using both glob+rglob double-counted top-level files
    js_files = sorted({str(p) for p in target_dir.rglob("*.js")})
    if not js_files:
        Log.warn("No JS files to analyse")
        return None, None

    def jsluice_run(subcommand, output_path):
        # argv can overflow with very large file lists; chunk to ~500 files per call
        with output_path.open("w") as out:
            for i in range(0, len(js_files), JSLUICE_BATCH_SIZE):
                chunk = js_files[i:i + JSLUICE_BATCH_SIZE]
                try:
                    result = subprocess.run(
                        ["jsluice", subcommand] + chunk,
                        capture_output=True, text=True, timeout=JSLUICE_TIMEOUT,
                    )
                except subprocess.TimeoutExpired:
                    Log.warn(f"jsluice {subcommand} timed out on batch {i // BATCH + 1}")
                    continue
                if result.stdout:
                    out.write(result.stdout)
                    if not result.stdout.endswith("\n"):
                        out.write("\n")

    jsluice_run("urls", endpoints_json)
    jsluice_run("secrets", secrets_json)

    # Filter out non-endpoint noise that jsluice's stringLiteral extractor picks up:
    # webpack module imports (`./auth/index.js`), source-map internal schemes
    # (`webpack://`, `webpack:///`, `file://`), and bare relative file paths.
    # These are JavaScript module paths, NOT reachable network URLs.
    raw_count = filtered_count = 0
    if endpoints_json.exists():
        kept_lines: list[str] = []
        for line in endpoints_json.open():
            if not line.strip():
                continue
            raw_count += 1
            try:
                rec = json.loads(line)
            except Exception:
                continue
            url = (rec.get("url") or "").strip()
            if not url:
                continue
            # Schemes that are clearly internal-only:
            lower = url.lower()
            if lower.startswith(("webpack://", "webpack:///", "file://",
                                  "blob:", "data:", "chrome-extension://",
                                  "moz-extension://", "javascript:", "mailto:",
                                  "tel:", "sms:", "intent:", "android-app://",
                                  "ios-app://", "about:")):
                continue
            # Relative module imports — never a real network endpoint:
            if url.startswith(("./", "../")):
                continue
            # Source-map internal markers
            if "webpack://" in lower or "webpack:///" in lower:
                continue
            # JS/TS/CSS/etc file extensions on a clearly module-shaped path
            # (single segment, no method, no query) are almost certainly imports
            if (url.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
                              ".css", ".scss", ".less", ".vue", ".svelte"))
                and not url.startswith(("http://", "https://", "//", "/"))):
                continue
            kept_lines.append(line if line.endswith("\n") else line + "\n")
            filtered_count += 1
        endpoints_json.write_text("".join(kept_lines))

    dropped = raw_count - filtered_count
    if dropped > 0:
        Log.verbose(f"dropped {dropped} non-endpoint reference(s) (webpack imports / module paths)")

    endpoint_count = filtered_count
    secret_count = sum(1 for line in secrets_json.open() if line.strip())
    msg = f"{endpoint_count} endpoint references"
    if dropped > 0:
        msg += f" ({dropped} module-import noise filtered out)"
    msg += f", {secret_count} secret candidates"
    Log.info(f"    {C.GREEN}[+]{C.RESET} {msg}")
    if secret_count > 0:
        Log.info(f"    {C.DIM}↳ Pattern-based matches, expect false positives — review secrets.json{C.RESET}")
    return endpoints_json, secrets_json


# ---------- Stage 5: Live endpoint validation ----------

def validate_endpoints(target, endpoints_file, output_dir, headers):
    """Hit each in-scope endpoint to determine which are live."""
    import urllib.request
    import urllib.error
    import ssl
    import re
    from concurrent.futures import ThreadPoolExecutor, as_completed

    stage_header(5, "Live endpoint validation")

    if not endpoints_file or not Path(endpoints_file).exists():
        Log.info("    [-] No endpoints file to validate")
        return None

    target_parsed = urlparse(target)
    target_host = target_parsed.hostname or ""
    target_base = f"{target_parsed.scheme}://{target_parsed.netloc}"

    # Build absolute URL set from JSluice endpoints
    endpoints = parse_jsonl(endpoints_file)
    urls = set()
    for e in endpoints:
        url = (e.get("url") or "").strip()
        if not url or not is_in_scope(url, target_host):
            continue
        # Build absolute URL
        if url.startswith(("http://", "https://")):
            full = url
        elif url.startswith("//"):
            full = "https:" + url
        elif url.startswith("/"):
            full = target_base + url
        else:
            full = target_base + "/" + url
        full = full.split("#")[0]  # drop fragment
        urls.add(full)

    if not urls:
        Log.info("    [-] No in-scope URLs to validate")
        return None

    # Smart ordering when over the cap: API-shaped paths first (more interesting
    # for security review), then short paths (often roots/admin), then content URLs
    # (blog posts, /docs/very/long/path) last. Within each tier we sort
    # alphabetically for deterministic output across runs.
    def _priority(u):
        path = urlparse(u).path.lower()
        # Tier 0: explicitly API-shaped
        if any(seg in path for seg in
               ("/api/", "/rest/", "/graphql", "/v1/", "/v2/", "/v3/",
                "/v4/", "/oauth", "/auth/", "/admin", "/login", "/logout",
                "/register", "/account", "/user/", "/users/", "/.well-known/")):
            return (0, len(path), u)
        # Tier 1: short paths (≤3 segments) — often roots or top-level pages
        seg_count = path.count('/')
        if seg_count <= 3:
            return (1, seg_count, u)
        # Tier 2: everything else (deep content / blog / docs)
        return (2, seg_count, u)

    url_list = sorted(urls, key=_priority)
    total_in_scope = len(url_list)
    truncated = False
    if total_in_scope > MAX_ENDPOINTS_TO_VALIDATE:
        Log.warn(f"{total_in_scope} in-scope URLs — validating {MAX_ENDPOINTS_TO_VALIDATE} "
                 f"highest-priority (API/short paths first). "
                 f"Use --max-endpoints 0 for unlimited.")
        url_list = url_list[:MAX_ENDPOINTS_TO_VALIDATE]
        truncated = True
    # Persist the truncation marker so the report can surface it.
    (output_dir / "live-endpoints-meta.json").write_text(json.dumps({
        "total_in_scope": total_in_scope,
        "validated": len(url_list),
        "truncated": truncated,
        "cap": MAX_ENDPOINTS_TO_VALIDATE,
    }))
    Log.info(f"    {C.GREEN}[+]{C.RESET} Probing {len(url_list)} URLs "
             f"({THREAD_POOL_WORKERS} concurrent, {ENDPOINT_CHECK_TIMEOUT}s timeout)")

    header_dict = parse_headers(headers)
    ctx = permissive_ssl_context()

    title_re = re.compile(rb"<title[^>]*>([^<]+)</title>", re.IGNORECASE)

    def check(url):
        try:
            req = urllib.request.Request(url, headers=header_dict, method="GET")
            with urllib.request.urlopen(req, context=ctx, timeout=ENDPOINT_CHECK_TIMEOUT) as resp:
                status = resp.status
                ct = resp.headers.get("Content-Type", "") or ""
                cl_hdr = resp.headers.get("Content-Length", "")
                body = b""
                # Read a small chunk for HTML to extract title
                if "html" in ct.lower():
                    body = resp.read(8192)
                title = None
                if body:
                    m = title_re.search(body)
                    if m:
                        title = m.group(1).decode("utf-8", errors="replace").strip()[:120]
                size = int(cl_hdr) if cl_hdr.isdigit() else (len(body) if body else None)
                return {"url": url, "status": status, "size": size,
                        "content_type": ct.split(";")[0].strip(), "title": title}
        except urllib.error.HTTPError as e:
            return {"url": url, "status": e.code, "size": None,
                    "content_type": "", "title": None}
        except Exception as e:
            return {"url": url, "status": None, "error": str(e)[:60],
                    "size": None, "content_type": "", "title": None}

    results = []
    with ThreadPoolExecutor(max_workers=THREAD_POOL_WORKERS) as pool:
        futures = [pool.submit(check, u) for u in url_list]
        for fut in as_completed(futures):
            results.append(fut.result())

    output_file = output_dir / "live-endpoints.json"
    with output_file.open("w") as f:
        for r in results:
            f.write(json.dumps(r) + "\n")

    # Summary by status class
    by_class = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "error": 0}
    auth_protected = 0
    for r in results:
        s = r.get("status")
        if s is None:
            by_class["error"] += 1
        elif 200 <= s < 300:
            by_class["2xx"] += 1
        elif 300 <= s < 400:
            by_class["3xx"] += 1
        elif 400 <= s < 500:
            by_class["4xx"] += 1
            if s in (401, 403):
                auth_protected += 1
        elif 500 <= s < 600:
            by_class["5xx"] += 1

    Log.info(f"    {C.GREEN}[+]{C.RESET} 2xx: {by_class['2xx']}  3xx: {by_class['3xx']}  "
             f"4xx: {by_class['4xx']} ({auth_protected} auth-protected)  "
             f"5xx: {by_class['5xx']}  errors: {by_class['error']}")
    if auth_protected > 0:
        Log.info(f"    {C.DIM}↳ {auth_protected} auth-protected endpoint(s) — priority targets, real functionality lives behind these{C.RESET}")
    if by_class["5xx"] > 0:
        Log.info(f"    {C.DIM}↳ {by_class['5xx']} server error(s) — often interesting, check with crafted input{C.RESET}")
    return output_file


# ---------- Stage 5b: Static metadata analysis ----------

# Curated comment patterns — devs leak intent in comments more than they realize.
COMMENT_PATTERNS = [
    (re.compile(r"//\s*TODO[:\s].{5,200}", re.IGNORECASE), "todo"),
    (re.compile(r"//\s*FIXME[:\s].{5,200}", re.IGNORECASE), "fixme"),
    (re.compile(r"//\s*HACK[:\s].{5,200}", re.IGNORECASE), "hack"),
    (re.compile(r"//\s*XXX[:\s].{5,200}", re.IGNORECASE), "xxx"),
    (re.compile(r"//[^\n]*\b(remove\s+before|delete\s+this|for\s+testing|temporary)\b[^\n]{0,150}", re.IGNORECASE), "leftover"),
    (re.compile(r"//[^\n]*\b(dev\b|staging|internal|debug\s+only)[^\n]{0,150}", re.IGNORECASE), "env_reference"),
    (re.compile(r"//[^\n]*\b(password|credential|secret|api[_-]?key|token)\b[^\n]{0,150}", re.IGNORECASE), "credential_mention"),
    (re.compile(r"/\*\s*eslint-disable[^*]{0,200}\*/", re.IGNORECASE), "lint_disabled"),
    (re.compile(r"//[^\n]*\b(CVE-\d{4}-\d{4,7})\b[^\n]{0,150}", re.IGNORECASE), "cve_reference"),
    (re.compile(r"//[^\n]*\b([A-Z]{2,10}-\d{2,6})\b[^\n]{0,150}"), "ticket_reference"),
    (re.compile(r"//[^\n]*@(author|maintainer|owner)[:\s]+[^\n]{3,100}", re.IGNORECASE), "authorship"),
    (re.compile(r"//[^\n]{0,150}\bhttps?://[^\s<>'\"]+\.(corp|internal|local|intra)\b[^\s<>'\"]*", re.IGNORECASE), "internal_url"),
]

# JSON files worth surfacing as exposures.
SENSITIVE_JSON_NAMES = {
    "appsettings.json", "web.config.json", "secrets.json", "credentials.json",
    "auth.json", "firebase.json", ".firebaserc", "config.json",
    "settings.json", "private.json", "database.json", ".env.json",
}

# Suspicious keys we look for inside any JSON file
SENSITIVE_JSON_KEYS = re.compile(
    r"\b(password|passwd|secret|api[_-]?key|apikey|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|aws[_-]?secret|connectionstring|"
    r"connection_string|database_url|mongodb_uri|jwt[_-]?secret|"
    r"auth_token|bearer)\b",
    re.IGNORECASE,
)


def static_metadata_analysis(js_clean, output_dir, target, headers):
    """
    Three static analyses on the JS corpus:
      1. Source map exposure findings
      2. JSON file discovery (Swagger/OpenAPI, config files, sensitive keys)
      3. Developer comments (TODO/FIXME, internal URLs, credential mentions)
    """
    import urllib.request
    import urllib.error
    import ssl
    import base64
    import hashlib

    stage_header("5b", "Static metadata analysis (maps, JSON, comments)")

    target_parsed = urlparse(target)
    target_host = target_parsed.hostname or ""
    target_base = f"{target_parsed.scheme}://{target_parsed.netloc}"

    header_dict = parse_headers(headers)

    def fetch(url):
        return fetch_url(url, headers=header_dict, timeout=ENDPOINT_CHECK_TIMEOUT)

    # === Part 1: Source map exposures ===
    Log.verbose("scanning corpus for source map references")
    exposed_maps = []          # [{url, status, source_file}]
    inline_maps_decoded = 0
    fetched_maps = 0

    sources_dir = output_dir / "sources"

    for jsfile in js_clean.glob("*.js"):
        try:
            content = jsfile.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for line in content.splitlines():
            if "sourceMappingURL=" not in line:
                continue
            ref = line.split("sourceMappingURL=", 1)[1].strip().strip("*/ ")
            if not ref:
                continue

            # Inline base64-encoded source map
            if ref.startswith("data:application/json;base64,"):
                try:
                    b64 = ref.split(",", 1)[1]
                    decoded = base64.b64decode(b64).decode("utf-8", errors="replace")
                    sources_dir.mkdir(exist_ok=True)
                    h = hashlib.sha1(b64.encode()).hexdigest()[:8]
                    map_path = sources_dir / f"inline-{h}.map"
                    map_path.write_text(decoded, encoding="utf-8", errors="replace")
                    # Extract embedded source files immediately — no external tool needed.
                    _, written = _extract_map_sources(map_path, sources_dir)
                    inline_maps_decoded += 1
                    if written:
                        Log.debug(f"extracted {written} source file(s) from inline map in {jsfile.name}")
                    else:
                        Log.debug(f"decoded inline source map from {jsfile.name}")
                except Exception as e:
                    Log.debug(f"inline map decode failed: {e}")
                continue

            # External map — resolve URL and probe
            if ref.startswith(("http://", "https://")):
                map_url = ref
            elif ref.startswith("//"):
                map_url = f"{target_parsed.scheme}:{ref}"
            elif ref.startswith("/"):
                map_url = target_base + ref
            else:
                # Relative to the JS file — best-effort guess from filename
                # We don't have the original URL of jsfile, so use target base
                map_url = target_base + "/" + ref.lstrip("./")

            try:
                map_host = urlparse(map_url).hostname or ""
            except Exception:
                continue
            if not (map_host == target_host or map_host.endswith("." + target_host)):
                continue  # out of scope

            status, body = fetch(map_url)
            entry = {"url": map_url, "status": status, "source_file": jsfile.name}
            if status == 200 and body.strip().startswith(("{", "[")):
                sources_dir.mkdir(exist_ok=True)
                h = hashlib.sha1(map_url.encode()).hexdigest()[:8]
                map_local = sources_dir / f"fetched-{h}.map"
                if not map_local.exists():
                    map_local.write_text(body, encoding="utf-8", errors="replace")
                    fetched_maps += 1
                # Extract embedded source files and report the source paths found.
                src_paths, written = _extract_map_sources(map_local, sources_dir)
                if src_paths:
                    entry["source_paths"] = src_paths[:50]   # cap for JSON sanity
                if written:
                    Log.verbose(f"extracted {written} source file(s) from {map_url}")
                entry["exposed"] = True
                exposed_maps.append(entry)
            elif status and 400 <= status < 500:
                entry["exposed"] = False

    # --- Blind .map probing: try {js_url}.map for every downloaded JS file ---
    url_map_path = output_dir / "url-map.json"
    if url_map_path.exists() and target:
        try:
            url_map_data: dict[str, str] = json.loads(url_map_path.read_text())
        except Exception:
            url_map_data = {}
        already_probed = {e["url"] for e in exposed_maps}
        for _fname, js_url in url_map_data.items():
            map_url = js_url + ".map"
            if map_url in already_probed:
                continue
            try:
                map_host = urlparse(map_url).hostname or ""
            except Exception:
                continue
            if not (map_host == target_host or map_host.endswith("." + target_host)):
                continue
            status, body = fetch(map_url)
            if status == 200 and body.strip().startswith(("{", "[")):
                sources_dir.mkdir(exist_ok=True)
                h = hashlib.sha1(map_url.encode()).hexdigest()[:8]
                map_local = sources_dir / f"blind-{h}.map"
                if not map_local.exists():
                    map_local.write_text(body, encoding="utf-8", errors="replace")
                    fetched_maps += 1
                src_paths, written = _extract_map_sources(map_local, sources_dir)
                entry = {
                    "url": map_url, "status": status,
                    "source_file": _fname, "exposed": True,
                    "discovery": "blind-probe",
                }
                if src_paths:
                    entry["source_paths"] = src_paths[:50]
                if written:
                    Log.info(f"    {C.YELLOW}[!]{C.RESET} Blind probe found exposed map: {map_url} "
                             f"({written} source files extracted)")
                exposed_maps.append(entry)

    if exposed_maps or inline_maps_decoded or fetched_maps:
        maps_file = output_dir / "exposed-maps.json"
        with maps_file.open("w") as f:
            for m in exposed_maps:
                f.write(json.dumps(m) + "\n")
        if exposed_maps:
            Log.info(f"    {C.YELLOW}[!]{C.RESET} {len(exposed_maps)} exposed source map(s) "
                     f"reachable on {target_host}")
            Log.info(f"    {C.DIM}↳ Production maps reveal original code structure — report as a finding{C.RESET}")
        if fetched_maps:
            Log.info(f"    {C.GREEN}[+]{C.RESET} Fetched {fetched_maps} additional map(s) for extraction")
        if inline_maps_decoded:
            Log.info(f"    {C.GREEN}[+]{C.RESET} Decoded {inline_maps_decoded} inline base64 map(s)")
    else:
        Log.info("    [-] No source maps found")
        maps_file = None

    # === Part 2: JSON file discovery ===
    Log.verbose("scanning corpus for JSON references")
    json_refs = set()

    # Look for JSON URLs referenced in JS files
    JSON_REF_RE = re.compile(
        r"""['"`]([^'"`\s<>{}()]+?\.json(?:\?[^'"`\s<>]*)?)['"`]""",
        re.IGNORECASE,
    )
    for jsfile in js_clean.glob("*.js"):
        try:
            content = jsfile.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for m in JSON_REF_RE.finditer(content):
            ref = m.group(1).strip()
            # Resolve to absolute
            if ref.startswith(("data:", "blob:", "javascript:")):
                continue
            if ref.startswith(("http://", "https://")):
                url = ref
            elif ref.startswith("//"):
                url = f"{target_parsed.scheme}:{ref}"
            elif ref.startswith("/"):
                url = target_base + ref
            else:
                url = target_base + "/" + ref.lstrip("./")

            try:
                json_host = urlparse(url).hostname or ""
            except Exception:
                continue
            if json_host == target_host or json_host.endswith("." + target_host):
                json_refs.add(url)

    # Also probe well-known JSON paths even if not referenced
    well_known = [
        "/swagger.json", "/openapi.json", "/api-docs.json", "/api-docs",
        "/swagger/v1/swagger.json", "/swagger-resources",
        "/.well-known/openid-configuration",
        "/manifest.json", "/asset-manifest.json",
    ]
    for p in well_known:
        json_refs.add(target_base + p)

    Log.verbose(f"probing {len(json_refs)} JSON URL(s)")

    json_findings = []   # [{url, status, type, sensitive_keys, swagger_endpoints}]
    swagger_endpoints = []  # endpoints discovered from Swagger docs

    for url in json_refs:
        status, body = fetch(url)
        if status != 200 or not body.strip():
            continue
        if not body.strip().startswith(("{", "[")):
            continue
        try:
            data = json.loads(body)
        except Exception:
            continue

        finding = {"url": url, "status": status, "type": "unknown",
                   "sensitive_keys": [], "size": len(body)}

        # Swagger / OpenAPI detection
        if isinstance(data, dict) and (
            data.get("swagger") or data.get("openapi")
            or ("paths" in data and isinstance(data.get("paths"), dict))
        ):
            finding["type"] = "swagger" if data.get("swagger") else "openapi"
            paths = data.get("paths", {})
            for path, methods in paths.items():
                if not isinstance(methods, dict):
                    continue
                for method, spec in methods.items():
                    if method.upper() in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
                        body_params = []
                        query_params = []
                        if isinstance(spec, dict):
                            for param in spec.get("parameters", []) or []:
                                if not isinstance(param, dict):
                                    continue
                                if param.get("in") == "query":
                                    query_params.append(param.get("name", ""))
                                elif param.get("in") == "body":
                                    body_params.append(param.get("name", "body"))
                            if spec.get("requestBody"):
                                body_params.append("body")
                        swagger_endpoints.append({
                            "url": path,
                            "method": method.upper(),
                            "queryParams": [p for p in query_params if p],
                            "bodyParams": [p for p in body_params if p],
                            "type": "swagger",
                            "filename": url,
                        })
            Log.debug(f"swagger doc at {url}: {len(paths)} paths extracted")

        # Sensitive keys scan
        found_keys = sorted({m.group(1).lower() for m in SENSITIVE_JSON_KEYS.finditer(body)})
        if found_keys:
            finding["sensitive_keys"] = found_keys
            finding["type"] = finding["type"] if finding["type"] != "unknown" else "config"

        # Sensitive filename check
        fname = url.rsplit("/", 1)[-1].split("?")[0].lower()
        if fname in SENSITIVE_JSON_NAMES:
            finding["type"] = "sensitive_config"

        # Only record if interesting
        if finding["type"] != "unknown" or finding["sensitive_keys"]:
            json_findings.append(finding)

    json_file = None
    if json_findings:
        json_file = output_dir / "json-exposures.json"
        with json_file.open("w") as f:
            for j in json_findings:
                f.write(json.dumps(j) + "\n")
        types = {}
        for j in json_findings:
            types[j["type"]] = types.get(j["type"], 0) + 1
        type_str = ", ".join(f"{n} {t}" for t, n in types.items())
        Log.info(f"    {C.GREEN}[+]{C.RESET} {len(json_findings)} JSON finding(s): {type_str}")
    if swagger_endpoints:
        sw_file = output_dir / "swagger-endpoints.json"
        with sw_file.open("w") as f:
            for e in swagger_endpoints:
                f.write(json.dumps(e) + "\n")
        Log.info(f"    {C.GREEN}[+]{C.RESET} {len(swagger_endpoints)} endpoint(s) extracted from Swagger/OpenAPI docs")
        Log.info(f"    {C.DIM}↳ Full API surface documented — often reveals admin/internal routes the SPA doesn't expose{C.RESET}")
    if not json_findings and not swagger_endpoints:
        Log.info("    [-] No JSON exposures or API docs found")

    # === Part 3: Developer comments ===
    Log.verbose("grepping corpus for interesting comments")
    comment_findings = []
    seen_lines = set()  # dedupe identical comments across files

    for jsfile in js_clean.glob("*.js"):
        try:
            content = jsfile.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for pattern, kind in COMMENT_PATTERNS:
            for m in pattern.finditer(content):
                text = m.group(0).strip()
                # Truncate excessively long matches
                if len(text) > 250:
                    text = text[:250] + "…"
                # Skip license headers (very common false positive)
                if any(noise in text.lower() for noise in [
                    "@license", "licensed under", "all rights reserved",
                    "creative commons", "redistributions of source",
                ]):
                    continue
                key = (kind, text)
                if key in seen_lines:
                    continue
                seen_lines.add(key)
                # Compute line number
                line_num = content[:m.start()].count("\n") + 1
                comment_findings.append({
                    "kind": kind,
                    "text": text,
                    "file": jsfile.name,
                    "line": line_num,
                })

    comments_file = None
    if comment_findings:
        comments_file = output_dir / "comments.json"
        with comments_file.open("w") as f:
            for c in comment_findings:
                f.write(json.dumps(c) + "\n")
        by_kind = {}
        for c in comment_findings:
            by_kind[c["kind"]] = by_kind.get(c["kind"], 0) + 1
        kind_str = ", ".join(f"{n} {k}" for k, n in sorted(by_kind.items(), key=lambda x: -x[1])[:5])
        Log.info(f"    {C.GREEN}[+]{C.RESET} {len(comment_findings)} comment finding(s): {kind_str}")
    else:
        Log.info("    [-] No interesting developer comments found")

    return {
        "maps_file": maps_file,
        "json_file": json_file,
        "swagger_endpoints_file": output_dir / "swagger-endpoints.json" if swagger_endpoints else None,
        "comments_file": comments_file,
        "exposed_maps": len(exposed_maps),
        "json_findings": len(json_findings),
        "swagger_endpoints": len(swagger_endpoints),
        "comments": len(comment_findings),
    }


# ---------- Stage 5d: Wayback Machine historical map discovery ----------

_CDX_API = "https://web.archive.org/cdx/search/cdx"
_WB_FETCH = "https://web.archive.org/web/{timestamp}id_/{url}"
_CDX_TIMEOUT = 30   # seconds — CDX can be slow
_WB_DL_TIMEOUT = 20


def query_wayback_maps(target: str, output_dir: Path, headers: list[str]) -> dict:
    """
    Stage 5d — Query the Wayback Machine CDX API for historically captured
    *.js.map files belonging to the target domain, download any that are not
    already present on the live site, extract their source content, and write
    a wayback-maps.json findings file.

    Returns a dict with keys:
      wayback_maps_file  – Path or None
      wayback_maps_count – int
      wayback_only_count – int  (maps not reachable on live site)
    """
    import urllib.request
    import urllib.error
    import ssl
    import hashlib
    import time

    stage_header("5d", "Wayback Machine — historical source map discovery")

    if not target:
        Log.info("    [-] Skipped (no --url provided)")
        return {"wayback_maps_file": None, "wayback_maps_count": 0, "wayback_only_count": 0}

    parsed = urlparse(target)
    domain = parsed.hostname or ""
    if not domain:
        Log.info("    [-] Could not determine domain from URL")
        return {"wayback_maps_file": None, "wayback_maps_count": 0, "wayback_only_count": 0}

    header_dict = parse_headers(headers)
    sources_dir = output_dir / "sources"

    # --- Step 1: CDX query ---
    cdx_params = {
        "url": f"{domain}/*.js.map",
        "output": "json",
        "fl": "original,timestamp,statuscode",
        "filter": "statuscode:200",
        "collapse": "urlkey",        # one entry per unique URL
        "limit": "200",              # reasonable cap
    }
    import urllib.parse as _urlparse
    cdx_url = _CDX_API + "?" + _urlparse.urlencode(cdx_params)
    Log.verbose(f"CDX query: {cdx_url}")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        req = urllib.request.Request(cdx_url, headers={"User-Agent": "Mozilla/5.0 jspect/1.0"})
        with urllib.request.urlopen(req, timeout=_CDX_TIMEOUT, context=ctx) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        cdx_rows: list[list[str]] = json.loads(raw)
    except Exception as exc:
        Log.warn(f"    [!] CDX API error: {exc}")
        return {"wayback_maps_file": None, "wayback_maps_count": 0, "wayback_only_count": 0}

    # CDX returns a header row then data rows [[original,timestamp,statuscode], ...]
    if not cdx_rows or len(cdx_rows) < 2:
        Log.info("    [-] No historical .js.map files found in Wayback Machine")
        return {"wayback_maps_file": None, "wayback_maps_count": 0, "wayback_only_count": 0}

    header_row = cdx_rows[0]
    data_rows  = cdx_rows[1:]
    try:
        idx_url = header_row.index("original")
        idx_ts  = header_row.index("timestamp")
    except ValueError:
        Log.warn("    [!] Unexpected CDX response format")
        return {"wayback_maps_file": None, "wayback_maps_count": 0, "wayback_only_count": 0}

    Log.info(f"    [+] CDX returned {len(data_rows)} unique historical map URL(s)")

    # --- Step 2: check which are still live, download the rest from archive ---
    findings: list[dict] = []
    wayback_only = 0

    for row in data_rows:
        orig_url  = row[idx_url]
        timestamp = row[idx_ts]

        # Probe the live URL first — if still accessible, Stage 5b already has it
        live_status, _ = fetch_url(orig_url, headers=header_dict, timeout=_WB_DL_TIMEOUT)
        is_live = live_status == 200

        # Download the archived copy regardless — it may differ from the live version
        wb_url = _WB_FETCH.format(timestamp=timestamp, url=orig_url)
        try:
            req2 = urllib.request.Request(wb_url, headers={"User-Agent": "Mozilla/5.0 jspect/1.0"})
            with urllib.request.urlopen(req2, timeout=_WB_DL_TIMEOUT, context=ctx) as resp2:
                wb_status  = resp2.getcode()
                wb_body    = resp2.read().decode("utf-8", errors="replace")
        except Exception:
            wb_body   = ""
            wb_status = None

        if not wb_body.strip().startswith(("{", "[")):
            # Not valid JSON — Wayback served an error page or HTML
            continue

        h = hashlib.sha1(orig_url.encode()).hexdigest()[:8]
        map_local = output_dir / "js_clean" / f"wayback-{h}.js.map"
        if not map_local.exists():
            map_local.write_text(wb_body, encoding="utf-8", errors="replace")

        src_paths, written = _extract_map_sources(map_local, sources_dir)

        entry: dict = {
            "url":          orig_url,
            "timestamp":    timestamp,
            "archive_url":  wb_url,
            "is_live":      is_live,
            "sources_extracted": written,
        }
        if src_paths:
            entry["source_paths"] = src_paths[:50]

        findings.append(entry)

        if not is_live:
            wayback_only += 1
            Log.info(
                f"    {C.YELLOW}[!]{C.RESET} Historical map (not on live site): {orig_url} "
                f"(captured {timestamp[:8]}, {written} source file(s) extracted)"
            )
        else:
            Log.verbose(f"historical map still live: {orig_url} ({written} source file(s))")

        # Brief pause to be polite to the Wayback CDX API
        time.sleep(0.3)

    if not findings:
        Log.info("    [-] No valid historical maps could be downloaded")
        return {"wayback_maps_file": None, "wayback_maps_count": 0, "wayback_only_count": 0}

    wb_file = output_dir / "wayback-maps.json"
    with wb_file.open("w") as f:
        for entry in findings:
            f.write(json.dumps(entry) + "\n")

    if wayback_only:
        Log.info(
            f"    {C.YELLOW}[!]{C.RESET} {wayback_only} map(s) exist ONLY in the archive — "
            f"previously exposed, now removed from production"
        )
        Log.info(
            f"    {C.DIM}↳ These maps may contain secrets that were live in a past deployment{C.RESET}"
        )

    total_extracted = sum(e.get("sources_extracted", 0) for e in findings)
    if total_extracted:
        Log.info(f"    {C.GREEN}[+]{C.RESET} Extracted {total_extracted} total source file(s) from Wayback maps")

    return {
        "wayback_maps_file":  wb_file,
        "wayback_maps_count": len(findings),
        "wayback_only_count": wayback_only,
    }


# ---------- Stage 4b: Active recon — Google dorks + broad Wayback discovery ----------

# Extensions worth pulling for static analysis. Each entry maps an extension to
# (human label, classifier — where to put the file: "js"/"map"/"recon").
_RECON_EXTENSIONS: dict[str, tuple[str, str]] = {
    "js":         ("JavaScript",          "js"),
    "mjs":        ("ES module",           "js"),
    "jsx":        ("JSX component",       "js"),
    "ts":         ("TypeScript",          "js"),
    "tsx":        ("TSX component",       "js"),
    "map":        ("Source map",          "map"),
    "json":       ("JSON",                "recon"),
    "yml":        ("YAML config",         "recon"),
    "yaml":       ("YAML config",         "recon"),
    "env":        ("Environment file",    "recon"),
    "config":     ("Configuration",       "recon"),
    "conf":       ("Configuration",       "recon"),
    "cfg":        ("Configuration",       "recon"),
    "ini":        ("INI configuration",   "recon"),
    "xml":        ("XML",                 "recon"),
    "txt":        ("Text",                "recon"),
    "bak":        ("Backup",              "recon"),
    "old":        ("Old/backup",          "recon"),
    "log":        ("Log",                 "recon"),
    "sql":        ("SQL dump",            "recon"),
    "csv":        ("CSV data",            "recon"),
}

# Hand-picked Google dork suffixes (joined to "site:{domain} ...") that surface
# the kinds of files the static analyzer eats.
_GOOGLE_DORK_SUFFIXES: list[tuple[str, str]] = [
    # File-type extension dorks
    ("ext:js",                           "JavaScript files indexed by Google"),
    ("ext:map",                          "Source maps indexed by Google"),
    ("ext:json",                         "JSON files indexed by Google"),
    ("ext:yml OR ext:yaml",              "YAML config files"),
    ("ext:env OR ext:config OR ext:conf","Environment / config files"),
    ("ext:ini",                          "INI config files"),
    ("ext:xml",                          "XML files"),
    ("ext:txt",                          "Text files"),
    ("ext:bak OR ext:old OR ext:backup", "Backup files"),
    ("ext:log",                          "Log files"),
    ("ext:sql",                          "SQL dumps"),
    # Path / filename dorks
    ('inurl:"swagger" OR inurl:"api-docs" OR inurl:"openapi"', "API documentation endpoints"),
    ('inurl:".git" OR inurl:".env" OR inurl:".DS_Store"', "Exposed dotfiles"),
    ('inurl:"wp-config" OR inurl:"web.config" OR inurl:"appsettings.json"', "Framework configs"),
    ('inurl:"sitemap.xml" OR inurl:"robots.txt"', "Sitemap / robots metadata"),
    ('inurl:".well-known"',              ".well-known endpoints"),
    # Content dorks
    ('intext:"-----BEGIN RSA PRIVATE KEY-----"', "Exposed RSA private keys"),
    ('intext:"BEGIN OPENSSH PRIVATE KEY"', "Exposed SSH private keys"),
    ('intext:"AKIA" intext:"aws_secret_access_key"', "AWS credentials in pages"),
]


def _generate_google_dorks(domain: str) -> list[dict]:
    """Build the dork query list with clickable URLs."""
    import urllib.parse as _up
    dorks = []
    for suffix, purpose in _GOOGLE_DORK_SUFFIXES:
        q = f"site:{domain} {suffix}"
        dorks.append({
            "query":   q,
            "purpose": purpose,
            "url":     f"https://www.google.com/search?q={_up.quote(q)}",
        })
    return dorks


def _google_cse_search(query: str, api_key: str, cse_id: str,
                       max_results: int = 30) -> list[str]:
    """Hit Google Custom Search JSON API. Returns list of result URLs.
    Free tier: 100 queries/day. Silent failure on quota / network errors.
    """
    import urllib.request
    import urllib.parse as _up
    urls: list[str] = []
    for start in range(1, min(max_results, 100) + 1, 10):
        api_url = (
            "https://www.googleapis.com/customsearch/v1?"
            f"key={_up.quote(api_key)}&cx={_up.quote(cse_id)}"
            f"&q={_up.quote(query)}&start={start}&num=10"
        )
        try:
            req = urllib.request.Request(api_url,
                headers={"User-Agent": "Mozilla/5.0 jspect/1.0"})
            with urllib.request.urlopen(req, timeout=15,
                                        context=permissive_ssl_context()) as r:
                data = json.loads(r.read().decode("utf-8", "replace"))
        except Exception as exc:
            Log.debug(f"CSE error for {query[:60]}: {exc}")
            break
        items = data.get("items", [])
        for it in items:
            link = it.get("link")
            if link:
                urls.append(link)
        if len(items) < 10:
            break
    return urls


def _query_cdx_for_ext(domain: str, ext: str, limit: int = 200) -> list[tuple[str, str]]:
    """Query the Wayback CDX API for one extension. Returns [(orig_url, timestamp), …]."""
    import urllib.request
    import urllib.parse as _up
    params = {
        "url":      f"{domain}/*.{ext}",
        "output":   "json",
        "fl":       "original,timestamp,statuscode",
        "filter":   "statuscode:200",
        "collapse": "urlkey",
        "limit":    str(limit),
    }
    url = _CDX_API + "?" + _up.urlencode(params)
    try:
        req = urllib.request.Request(url,
            headers={"User-Agent": "Mozilla/5.0 jspect/1.0"})
        with urllib.request.urlopen(req, timeout=_CDX_TIMEOUT,
                                    context=permissive_ssl_context()) as resp:
            rows = json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception as exc:
        Log.debug(f"CDX query failed for .{ext}: {exc}")
        return []
    if not rows or len(rows) < 2:
        return []
    try:
        idx_u = rows[0].index("original")
        idx_t = rows[0].index("timestamp")
    except ValueError:
        return []
    return [(r[idx_u], r[idx_t]) for r in rows[1:]]


def _classify_url(url: str) -> tuple[str, str, str] | None:
    """Return (ext, label, bucket) for a URL whose extension is in _RECON_EXTENSIONS.
    Returns None if the URL doesn't match any tracked extension.
    """
    path = urlparse(url).path.lower()
    # Match longest extension first (e.g. .js.map before .map would be wrong — we want .map)
    # but really we just want the final extension
    if "." not in path.rsplit("/", 1)[-1]:
        return None
    ext = path.rsplit(".", 1)[-1]
    # Strip query string artefacts
    ext = re.sub(r"[^a-z0-9]+.*$", "", ext)
    if ext in _RECON_EXTENSIONS:
        label, bucket = _RECON_EXTENSIONS[ext]
        return ext, label, bucket
    return None


def active_recon_discovery(target: str, output_dir: Path, headers: list[str],
                            js_clean: Path) -> dict:
    """
    Stage 4b — Aggressive file discovery via Google dorks + broad Wayback queries.

    Goal: feed as many static files as possible into the downstream analysis pipeline.
    - Generates Google dork URLs (always) and saves them to dorks.json
    - If GOOGLE_API_KEY + GOOGLE_CSE_ID env vars are set, also auto-fetches results
    - Queries Wayback CDX for every extension in _RECON_EXTENSIONS
    - Downloads each unique URL — live first, archive fallback
    - JS-like files land in js_clean/  (full Semgrep / JSluice / secret pipeline)
    - .map files land in js_clean/ AND get sourcesContent extracted into sources/
    - Configs / text / backups land in recon/ and get scanned for secrets

    Returns counters for the report.
    """
    import urllib.request
    import hashlib
    import time

    stage_header("4b", "Active recon — Google dorks + broad Wayback discovery")

    if not target:
        Log.info("    [-] Skipped (no --url provided)")
        return {"recon_summary_file": None, "recon_total_found": 0,
                "recon_downloaded": 0, "recon_secrets_found": 0,
                "dorks_file": None}

    domain = urlparse(target).hostname or ""
    if not domain:
        Log.info("    [-] Could not determine domain")
        return {"recon_summary_file": None, "recon_total_found": 0,
                "recon_downloaded": 0, "recon_secrets_found": 0,
                "dorks_file": None}

    recon_dir = output_dir / "recon"
    recon_dir.mkdir(exist_ok=True)
    sources_dir = output_dir / "sources"
    header_dict = parse_headers(headers)

    # ── Step 1: Google dorks ─────────────────────────────────────────
    Log.verbose("generating Google dork queries")
    dorks = _generate_google_dorks(domain)
    dorks_file = output_dir / "dorks.json"
    dorks_file.write_text(json.dumps(dorks, indent=2))
    Log.info(f"    [+] Generated {len(dorks)} Google dork URLs → dorks.json")

    candidate_urls: set[str] = set()

    api_key = os.environ.get("GOOGLE_API_KEY", "").strip()
    cse_id  = os.environ.get("GOOGLE_CSE_ID", "").strip()
    if api_key and cse_id:
        Log.info(f"    [+] Google CSE credentials detected — running {len(dorks)} live searches")
        cse_hits = 0
        for d in dorks:
            urls = _google_cse_search(d["query"], api_key, cse_id, max_results=20)
            if urls:
                Log.verbose(f"CSE {d['purpose']}: {len(urls)} result(s)")
            cse_hits += len(urls)
            for u in urls:
                if _classify_url(u):
                    candidate_urls.add(u)
            time.sleep(0.2)
        Log.info(f"    [+] Google CSE returned {cse_hits} total result(s), "
                 f"{len(candidate_urls)} with analyzable extensions")
    else:
        Log.info(f"    {C.DIM}[i] Set GOOGLE_API_KEY + GOOGLE_CSE_ID env vars to auto-fetch "
                 f"dork results (free tier: 100 queries/day){C.RESET}")

    # ── Step 2: Wayback CDX — one query per extension ────────────────
    Log.verbose(f"querying Wayback CDX for {len(_RECON_EXTENSIONS)} extension(s)")
    cdx_per_ext: dict[str, list[tuple[str, str]]] = {}
    for ext in _RECON_EXTENSIONS:
        rows = _query_cdx_for_ext(domain, ext, limit=200)
        if rows:
            cdx_per_ext[ext] = rows
            Log.verbose(f"CDX .{ext}: {len(rows)} historical URL(s)")
        time.sleep(0.25)   # be polite

    cdx_total = sum(len(v) for v in cdx_per_ext.values())
    if cdx_total:
        Log.info(f"    [+] Wayback CDX returned {cdx_total} historical URL(s) "
                 f"across {len(cdx_per_ext)} extension(s)")
        # Add Wayback URLs to candidate set
        for ext, rows in cdx_per_ext.items():
            for orig_url, _ts in rows:
                candidate_urls.add(orig_url)
    else:
        Log.info("    [-] No historical files indexed in Wayback for this domain")

    total_found = len(candidate_urls)
    if not candidate_urls:
        Log.info("    [-] No files discovered via dorks or Wayback")
        return {"recon_summary_file": None, "recon_total_found": 0,
                "recon_downloaded": 0, "recon_secrets_found": 0,
                "dorks_file": dorks_file}

    Log.info(f"    [+] {total_found} unique candidate URL(s) — downloading…")

    # Build a quick lookup of CDX timestamps for archive fallback
    ts_by_url: dict[str, str] = {}
    for rows in cdx_per_ext.values():
        for u, t in rows:
            ts_by_url.setdefault(u, t)

    # ── Step 3: Download every candidate ─────────────────────────────
    downloaded: list[dict] = []
    js_added = 0
    map_added = 0
    recon_added = 0

    # Track existing js_clean filenames to avoid clobbering
    existing_js = {p.name for p in js_clean.glob("*")}

    for idx, url in enumerate(sorted(candidate_urls), 1):
        cls = _classify_url(url)
        if not cls:
            continue
        ext, label, bucket = cls

        # Try live first
        status, body = fetch_url(url, headers=header_dict, timeout=15, max_bytes=5_000_000)
        source = "live"
        if status != 200 or not body:
            # Fallback to Wayback if we have a timestamp
            ts = ts_by_url.get(url)
            if ts:
                wb_url = _WB_FETCH.format(timestamp=ts, url=url)
                status, body = fetch_url(wb_url, headers=header_dict,
                                          timeout=_WB_DL_TIMEOUT, max_bytes=5_000_000)
                source = "wayback"
        if not body:
            continue

        # Build a stable, safe local filename
        h = hashlib.sha1(url.encode()).hexdigest()[:8]
        leaf = Path(urlparse(url).path).name or f"file.{ext}"
        safe_leaf = re.sub(r"[^\w.\-]", "_", leaf)[:80] or f"file.{ext}"
        fname = f"{h}-{safe_leaf}"

        if bucket == "js":
            # Feed JS into the existing pipeline
            if fname in existing_js:
                continue
            dest = js_clean / fname
            dest.write_text(body, encoding="utf-8", errors="replace")
            existing_js.add(fname)
            js_added += 1
        elif bucket == "map":
            # Drop into js_clean so map discovery still finds it, plus extract sources
            dest = js_clean / fname
            dest.write_text(body, encoding="utf-8", errors="replace")
            sources_dir.mkdir(exist_ok=True)
            _src_paths, _written = _extract_map_sources(dest, sources_dir)
            map_added += 1
        else:  # recon bucket
            dest = recon_dir / fname
            dest.write_text(body, encoding="utf-8", errors="replace")
            recon_added += 1

        downloaded.append({
            "url":   url,
            "ext":   ext,
            "label": label,
            "bucket": bucket,
            "source": source,
            "local": str(dest.relative_to(output_dir)),
            "size":  len(body),
        })

        if idx % 20 == 0:
            Log.verbose(f"downloaded {idx}/{total_found}…")

    Log.info(f"    [+] Downloaded {len(downloaded)} file(s): "
             f"{js_added} JS, {map_added} map, {recon_added} config/text/etc.")

    # ── Step 4: Secret scan recon/ files ─────────────────────────────
    secret_hits: list[dict] = []
    for f in recon_dir.glob("*"):
        if not f.is_file():
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if len(text) > 2_000_000:
            continue
        for pattern, kind in _SECRET_PATTERNS:
            for m in pattern.finditer(text):
                val = m.group(0)
                if len(val) > 500:
                    continue
                if kind in ("hex-secret", "uuid-token") and _shannon_entropy(val) < 3.5:
                    continue
                # Tiny context window
                start = max(0, m.start() - 30)
                end   = min(len(text), m.end() + 30)
                ctx_snip = text[start:end].replace("\n", " ")
                secret_hits.append({
                    "file":    f.name,
                    "kind":    kind,
                    "match":   val[:200],
                    "context": ctx_snip[:200],
                })

    sec_file = None
    if secret_hits:
        sec_file = output_dir / "recon-secrets.json"
        with sec_file.open("w") as fh:
            for s in secret_hits:
                fh.write(json.dumps(s) + "\n")
        Log.info(f"    {C.YELLOW}[!]{C.RESET} {len(secret_hits)} secret pattern hit(s) in recon files")
    else:
        Log.verbose("no secret patterns matched in recon files")

    # ── Step 5: Write summary ────────────────────────────────────────
    summary_file = output_dir / "recon-summary.json"
    with summary_file.open("w") as fh:
        for d in downloaded:
            fh.write(json.dumps(d) + "\n")

    return {
        "recon_summary_file":  summary_file,
        "recon_secrets_file":  sec_file,
        "recon_total_found":   total_found,
        "recon_downloaded":    len(downloaded),
        "recon_js_added":      js_added,
        "recon_map_added":     map_added,
        "recon_other_added":   recon_added,
        "recon_secrets_found": len(secret_hits),
        "dorks_file":          dorks_file,
    }


# ---------- Stage 4c: Well-known files (robots.txt, sitemap, .well-known/*) ----------

# Each entry: (path, category, description)
# Categories: discovery (URL harvesters), api-doc, policy (cross-origin trust),
#             leak (files that shouldn't be exposed), info (metadata)
_WELL_KNOWN_PATHS: list[tuple[str, str, str]] = [
    # URL inventories
    ("/robots.txt",                "discovery", "Disallow/Allow paths"),
    ("/sitemap.xml",               "discovery", "XML sitemap"),
    ("/sitemap_index.xml",         "discovery", "Sitemap index"),
    ("/sitemap.txt",               "discovery", "Plain text sitemap"),
    ("/sitemap-index.xml",         "discovery", "Sitemap index (alt)"),
    # Site/security info
    ("/humans.txt",                "info",      "Site authors"),
    ("/security.txt",              "info",      "Security disclosure"),
    ("/.well-known/security.txt",  "info",      "Standard security.txt"),
    ("/.well-known/change-password","info",     "Password change endpoint"),
    ("/.well-known/openid-configuration","api-doc","OIDC discovery"),
    ("/.well-known/oauth-authorization-server","api-doc","OAuth metadata"),
    ("/.well-known/assetlinks.json","info",     "Android app links"),
    ("/.well-known/apple-app-site-association","info","iOS universal links"),
    # Legacy cross-origin trust files — frequently leak trusted third-party domains
    ("/crossdomain.xml",           "policy",    "Flash cross-domain policy"),
    ("/clientaccesspolicy.xml",    "policy",    "Silverlight policy"),
    # API documentation (common default paths)
    ("/swagger.json",              "api-doc",   "Swagger spec"),
    ("/swagger/v1/swagger.json",   "api-doc",   "Swagger v1"),
    ("/api/swagger.json",          "api-doc",   "API Swagger"),
    ("/openapi.json",              "api-doc",   "OpenAPI spec"),
    ("/api-docs",                  "api-doc",   "API docs index"),
    ("/v2/api-docs",               "api-doc",   "Swagger 2.0 docs"),
    ("/v3/api-docs",               "api-doc",   "OpenAPI 3 docs"),
    ("/graphql",                   "api-doc",   "GraphQL endpoint"),
    # Common leftover / source-control leaks
    ("/.git/config",               "leak",      "Exposed git config"),
    ("/.git/HEAD",                 "leak",      "Exposed git HEAD"),
    ("/.svn/entries",              "leak",      "Exposed SVN repo"),
    ("/.hg/hgrc",                  "leak",      "Exposed Mercurial repo"),
    ("/.env",                      "leak",      "Exposed env file"),
    ("/.env.local",                "leak",      "Local env file"),
    ("/.env.production",           "leak",      "Production env file"),
    ("/.DS_Store",                 "leak",      "macOS metadata"),
    ("/Thumbs.db",                 "leak",      "Windows thumbnail metadata"),
    # Project manifests (reveal stack + dependencies)
    ("/package.json",              "leak",      "Node manifest"),
    ("/composer.json",             "leak",      "PHP composer manifest"),
    ("/Gemfile",                   "leak",      "Ruby Gemfile"),
    ("/requirements.txt",          "leak",      "Python requirements"),
    ("/yarn.lock",                 "leak",      "Yarn lockfile"),
    # PWA / build manifests (often reveal asset URLs)
    ("/manifest.json",             "info",      "PWA manifest"),
    ("/asset-manifest.json",       "info",      "Webpack asset manifest"),
    ("/precache-manifest.json",    "info",      "Workbox precache manifest"),
    # Ads / metadata
    ("/ads.txt",                   "info",      "Authorized sellers"),
    ("/app-ads.txt",               "info",      "Mobile ads.txt"),
]


def _parse_robots_txt(body: str, base: str) -> tuple[list[str], list[str]]:
    """Extract paths from Disallow/Allow rules and Sitemap: URLs.
    Returns (paths, sitemap_urls). Paths are absolute URLs based on `base`.
    """
    paths: list[str] = []
    sitemaps: list[str] = []
    for raw in body.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        lower = line.lower()
        if lower.startswith(("disallow:", "allow:")):
            val = line.split(":", 1)[1].strip()
            if val and val != "/" and "*" not in val:
                # Strip wildcards / trailing $
                p = val.split("$", 1)[0]
                if p.startswith("/"):
                    paths.append(base.rstrip("/") + p)
        elif lower.startswith("sitemap:"):
            val = line.split(":", 1)[1].strip()
            if val.startswith(("http://", "https://")):
                sitemaps.append(val)
    return paths, sitemaps


def _parse_sitemap_xml(body: str) -> tuple[list[str], list[str]]:
    """Extract <loc> URLs from a sitemap or sitemap-index. Returns (urls, sub_sitemaps).
    Pure-regex parse — handles CDATA-wrapped URLs (common in WordPress sitemaps).
    """
    # Grab everything between <loc> and </loc>, then strip optional CDATA wrapper.
    raw_locs = re.findall(r"<loc[^>]*>(.*?)</loc>", body,
                          flags=re.IGNORECASE | re.DOTALL)
    locs: list[str] = []
    for chunk in raw_locs:
        s = chunk.strip()
        m = re.match(r"<!\[CDATA\[\s*(.*?)\s*\]\]>", s, flags=re.DOTALL)
        if m:
            s = m.group(1).strip()
        if s:
            locs.append(s)

    sub_sitemaps: list[str] = []
    page_urls:    list[str] = []
    # Sitemap index files have <sitemapindex>...<sitemap><loc>...</loc></sitemap>;
    # URL sets have <urlset>...<url><loc>...</loc></url>.
    is_index = "<sitemapindex" in body.lower()
    for u in locs:
        if u.startswith(("http://", "https://")):
            (sub_sitemaps if is_index else page_urls).append(u)
    return page_urls, sub_sitemaps


def _parse_crossdomain_xml(body: str) -> list[str]:
    """Extract domains from <allow-access-from domain="..."/>. Wildcards included."""
    return re.findall(r'allow-access-from[^>]*\bdomain\s*=\s*["\']([^"\']+)["\']',
                      body, re.IGNORECASE)


def _looks_like_spa_catchall(body: str) -> bool:
    """True when a response body looks like an SPA's catch-all HTML shell —
    served with HTTP 200 for any unknown path (Facebook, React apps, etc.).
    Used to filter false-positive 'leaks'."""
    if not body:
        return False
    head = body.lstrip()[:500].lower()
    return head.startswith(("<!doctype html", "<html", "<!--", "<head"))


# Per-path content-shape validators. Each function returns True if the body
# is consistent with what the file is *supposed* to be — i.e. a true leak.
# When validation fails, the hit is a false positive (SPA catch-all, WAF
# challenge page, login wall, etc.) and is dropped from the leak list.
def _validate_leak_content(path: str, body: str) -> bool:
    if not body:
        return False
    bs = body.strip()
    head = bs[:500]
    head_l = head.lower()

    # Anything that looks like an HTML page where we expected non-HTML is bogus
    if _looks_like_spa_catchall(bs) and not path.endswith((".html", ".htm")):
        return False

    # File-specific shape checks
    if path in ("/package.json", "/composer.json", "/manifest.json",
                "/asset-manifest.json", "/precache-manifest.json"):
        try:
            json.loads(bs)
            return True
        except Exception:
            return False
    if path.startswith("/.env"):
        # .env is KEY=value lines. Must not contain HTML tags. Must contain '='
        # or be empty (some hosts serve 200 empty for missing files — skip).
        if "<html" in bs.lower() or "<!doctype" in bs.lower():
            return False
        return "=" in bs and not bs.startswith("{")
    if path == "/.git/config":
        return "[core]" in bs or bs.startswith("[")
    if path == "/.git/HEAD":
        return bs.startswith("ref:") or bool(re.match(r"^[0-9a-f]{40}\s*$", bs))
    if path == "/.svn/entries":
        return bs[:1].isdigit() or "<wc-status" in bs
    if path == "/.hg/hgrc":
        return bs.startswith("[") and "]" in head
    if path == "/Gemfile":
        return bool(re.search(r"\b(source|gem|ruby)\s+['\"]", bs))
    if path == "/requirements.txt":
        # Each non-comment line should be a package spec (name + optional version)
        lines = [l.strip() for l in bs.splitlines()
                 if l.strip() and not l.startswith("#")]
        if not lines:
            return False
        valid = sum(1 for l in lines if re.match(r"^[A-Za-z0-9_.\-]+([<>=!~].*)?$", l))
        return valid >= max(1, len(lines) // 2)
    if path == "/yarn.lock":
        return bs.startswith("# THIS IS AN AUTOGENERATED FILE") or '"@' in bs[:1000]
    if path in ("/.DS_Store", "/Thumbs.db"):
        # Binary files — should contain non-printable bytes; HTML wouldn't
        return any(ord(c) < 9 or (13 < ord(c) < 32) for c in bs[:200])

    # Unknown leak path → fall back to "must not be HTML"
    return not _looks_like_spa_catchall(bs)


def discover_well_known(target: str, output_dir: Path, headers: list[str],
                         endpoints_file: Path | None) -> dict:
    """
    Stage 4c — Probe a curated list of public/well-known files.

    Always passive: every probed path is meant to be public by convention.
    Outputs:
      - well-known.json  — every probed path, status, size, category
      - well-known-urls.txt — URLs harvested from robots.txt / sitemap(s)
      - well-known-trust.json — domains trusted via crossdomain/clientaccesspolicy
    Harvested URLs are also appended to endpoints_file so they flow through
    live validation / scope analysis downstream.
    """
    stage_header("4c", "Well-known files probe (robots, sitemap, .well-known/*, leaks)")

    if not target:
        Log.info("    [-] Skipped (no --url provided)")
        return {"well_known_file": None, "well_known_hits": 0,
                "well_known_harvested": 0, "well_known_leaks": 0,
                "well_known_trust_file": None}

    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"
    target_host = parsed.hostname or ""
    header_dict = parse_headers(headers)

    well_known_dir = output_dir / "well-known"
    well_known_dir.mkdir(exist_ok=True)

    findings: list[dict] = []
    harvested_urls: set[str] = set()
    sub_sitemaps_seen: set[str] = set()
    trust_domains: set[str] = set()
    leak_count = 0

    def _save(name: str, body: str) -> str:
        """Write body to well-known/ with a safe filename."""
        safe = re.sub(r"[^\w.\-]+", "_", name).strip("_") or "file"
        path = well_known_dir / safe
        path.write_text(body, encoding="utf-8", errors="replace")
        return str(path.relative_to(output_dir))

    for path, category, desc in _WELL_KNOWN_PATHS:
        url = base + path
        status, body = fetch_url(url, headers=header_dict, timeout=10, max_bytes=2_000_000)
        if status != 200 or not body:
            continue

        # Quick HTML-error sanity filter — many sites serve 200 + a friendly 404 page
        body_strip = body.strip()
        looks_html_error = (
            body_strip.lower().startswith("<!doctype html") and
            len(body_strip) < 8000 and
            ("404" in body_strip[:500] or "not found" in body_strip.lower()[:500])
        )
        if looks_html_error:
            continue

        local = _save(path.lstrip("/").replace("/", "__"), body)
        entry = {
            "path": path, "url": url, "category": category, "description": desc,
            "status": status, "size": len(body), "local": local,
        }

        # Per-category parsing
        if path == "/robots.txt":
            paths, sitemap_urls = _parse_robots_txt(body, base)
            entry["harvested_paths"] = len(paths)
            entry["sitemaps_referenced"] = sitemap_urls
            for p in paths:
                if (urlparse(p).hostname or target_host) == target_host:
                    harvested_urls.add(p)
            for sm in sitemap_urls:
                sub_sitemaps_seen.add(sm)
        elif "sitemap" in path:
            urls, sub_sm = _parse_sitemap_xml(body)
            entry["harvested_paths"] = len(urls)
            entry["sub_sitemaps"]    = sub_sm
            for u in urls:
                if (urlparse(u).hostname or "") == target_host:
                    harvested_urls.add(u)
            for s in sub_sm:
                sub_sitemaps_seen.add(s)
        elif path in ("/crossdomain.xml", "/clientaccesspolicy.xml"):
            domains = _parse_crossdomain_xml(body)
            entry["trusted_domains"] = domains
            for d in domains:
                trust_domains.add(d)
            if "*" in domains:
                entry["risk"] = "wildcard trust — any origin allowed"

        if category == "leak":
            # Validate that the response actually looks like the expected file —
            # SPA catch-alls and WAF challenge pages also return 200 OK with
            # totally unrelated content. Demote false positives to "info" so
            # the operator still sees the response but it doesn't pollute the
            # leak count / priority leads.
            if not _validate_leak_content(path, body):
                entry["category"] = "info"
                entry["original_category"] = "leak"
                entry["note"] = "200 OK but content doesn't match expected shape — likely SPA catch-all or WAF page"
                Log.verbose(f"demoted false-positive leak: {path} (catch-all response)")
            else:
                leak_count += 1
                Log.info(f"    {C.YELLOW}[!]{C.RESET} Leak: {url} ({desc}, {len(body):,}B)")
        else:
            Log.verbose(f"hit {path} ({category}, {len(body):,}B)")

        findings.append(entry)

    # Fetch any sitemap URLs referenced from robots.txt or sub-indexes
    extra_sitemaps = sub_sitemaps_seen - {f["url"] for f in findings}
    # Cap to avoid infinite recursion on malicious sitemaps
    for sm_url in list(extra_sitemaps)[:20]:
        if (urlparse(sm_url).hostname or "") != target_host:
            continue
        status, body = fetch_url(sm_url, headers=header_dict, timeout=10, max_bytes=2_000_000)
        if status != 200 or not body:
            continue
        urls, _sub = _parse_sitemap_xml(body)
        for u in urls:
            if (urlparse(u).hostname or "") == target_host:
                harvested_urls.add(u)
        findings.append({
            "path": urlparse(sm_url).path,
            "url": sm_url,
            "category": "discovery",
            "description": "Referenced sitemap",
            "status": status, "size": len(body),
            "local": _save("ref_" + re.sub(r"\W+", "_", sm_url)[-60:], body),
            "harvested_paths": len(urls),
        })
        Log.verbose(f"ref'd sitemap {sm_url}: {len(urls)} url(s)")

    # Persist findings
    wk_file = output_dir / "well-known.json"
    with wk_file.open("w") as fh:
        for f in findings:
            fh.write(json.dumps(f) + "\n")

    trust_file = None
    if trust_domains:
        trust_file = output_dir / "well-known-trust.json"
        trust_file.write_text(json.dumps(sorted(trust_domains), indent=2))
        Log.info(f"    {C.YELLOW}[!]{C.RESET} Cross-origin trust file(s) found — "
                 f"{len(trust_domains)} trusted domain(s): "
                 f"{', '.join(sorted(trust_domains)[:6])}"
                 f"{'…' if len(trust_domains) > 6 else ''}")

    # Merge harvested URLs into the main endpoints file (JSONL).
    # If jsluice never created an endpoints file (e.g. no JS files), create it so
    # the harvested URLs still flow into Stage 5 live validation.
    merged = 0
    if harvested_urls:
        # Default landing spot matches run_jsluice's output name
        if not endpoints_file:
            endpoints_file = output_dir / "endpoints.json"
        try:
            mode = "a" if endpoints_file.exists() else "w"
            with endpoints_file.open(mode, encoding="utf-8") as dst:
                for u in sorted(harvested_urls):
                    dst.write(json.dumps({
                        "url": u,
                        "method": "GET",
                        "type": "well-known",
                    }) + "\n")
                    merged += 1
        except OSError as exc:
            Log.warn(f"endpoints merge failed: {exc}")

    # Also write the harvested URL list as plaintext for easy fuzzing/feeding
    if harvested_urls:
        url_list_file = output_dir / "well-known-urls.txt"
        url_list_file.write_text("\n".join(sorted(harvested_urls)) + "\n")

    # Summary log
    summary_parts = [f"{len(findings)} file(s)"]
    if harvested_urls:
        summary_parts.append(f"{len(harvested_urls)} url(s) harvested")
    if leak_count:
        summary_parts.append(f"{leak_count} leak(s)")
    if trust_domains:
        summary_parts.append(f"{len(trust_domains)} trusted domain(s)")
    if findings:
        Log.info(f"    {C.GREEN}[+]{C.RESET} " + " · ".join(summary_parts))
    else:
        Log.info("    [-] No well-known files responded with 200")

    return {
        "well_known_file":      wk_file if findings else None,
        "well_known_hits":      len(findings),
        "well_known_harvested": len(harvested_urls),
        "well_known_leaks":     leak_count,
        "well_known_merged":    merged,
        "well_known_trust_file": trust_file,
        "well_known_trust_count": len(trust_domains),
        # Surface back so callers can adopt a newly-created endpoints file
        "endpoints_file_after_wk": endpoints_file if merged else None,
    }


# ---------- Stage 5c: HTTP call + hardcoded secret extraction ----------

# Patterns that find HTTP call URLs embedded in JS source.
# Split into client-side (browser) and server-side (Node.js/Express) buckets so
# the report can label them appropriately.
_HTTP_CALL_PATTERNS = [
    # ── Client-side: browser APIs ────────────────────────────────────────────
    # fetch("url")  or  fetch(`url`)
    (re.compile(r"""\bfetch\s*\(\s*["`']([^"`'\n]{4,200})["`']"""), "fetch"),
    # axios.METHOD("url")
    (re.compile(r"""\baxios\.(get|post|put|delete|patch|head)\s*\(\s*["`']([^"`'\n]{4,200})["`']""",
                re.IGNORECASE), "axios"),
    # this.http.METHOD("url")  / this._http.METHOD("url")  (Angular HttpClient)
    (re.compile(r"""this\._?http\.(get|post|put|delete|patch)\s*\(\s*["`']([^"`'\n]{4,200})["`']""",
                re.IGNORECASE), "angular-http"),
    # xhr.open("METHOD", "url")
    (re.compile(r"""\.open\s*\(\s*["']([A-Z]{3,7})["']\s*,\s*["`']([^"`'\n]{4,200})["`']"""), "xhr"),
    # $.ajax / $.get / $.post
    (re.compile(r"""\$\.(ajax|get|post)\s*\(\s*["`']([^"`'\n]{4,200})["`']""",
                re.IGNORECASE), "jquery"),
    # Authorization header literals
    (re.compile(r"""[Aa]uthorization["`']?\s*:\s*["`']([^"`'\n]{8,200})["`']"""), "auth-header"),

    # ── Server-side: Node.js HTTP clients ────────────────────────────────────
    # require('request')("url")  /  request.get("url")  /  request.post("url")
    (re.compile(r"""\brequest\.(get|post|put|delete|patch|head)\s*\(\s*["`']([^"`'\n]{4,200})["`']""",
                re.IGNORECASE), "node-request"),
    # Node built-in http/https: http.get("url") / https.request("url")
    (re.compile(r"""\bhttps?\.(get|request)\s*\(\s*["`']([^"`'\n]{4,200})["`']""",
                re.IGNORECASE), "node-http"),
    # got("url") — popular Node HTTP client
    (re.compile(r"""\bgot\.(get|post|put|delete|patch|head)\s*\(\s*["`']([^"`'\n]{4,200})["`']""",
                re.IGNORECASE), "node-got"),
    # superagent: agent.get("url") / agent.post("url")
    (re.compile(r"""\b(?:superagent|agent|sa)\.(get|post|put|delete|patch|head)\s*\(\s*["`']([^"`'\n]{4,200})["`']""",
                re.IGNORECASE), "superagent"),

    # ── Server-side: Express route definitions ───────────────────────────────
    # app.get("/path", ...)  /  router.post("/path", ...)
    (re.compile(r"""\b(?:app|router)\.(get|post|put|delete|patch|all|use)\s*\(\s*["`']([^"`'\n]{1,200})["`']""",
                re.IGNORECASE), "express-route"),
]

# Patterns for hardcoded secrets — complement TruffleHog (which works on the whole file;
# these give file+line context for the report).
_SECRET_PATTERNS = [
    # JWT tokens (full 3-part structure)
    (re.compile(r"eyJ[A-Za-z0-9\-_=]{10,}\.[A-Za-z0-9\-_=]{10,}\.[A-Za-z0-9\-_.+/=]{10,}"),
     "jwt"),
    # AWS key ID
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
     "aws-key-id"),
    # Google API key
    (re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
     "google-api-key"),
    # Stripe live/test key
    (re.compile(r"\b(?:sk|pk)_(?:live|test)_[0-9A-Za-z]{24,}\b"),
     "stripe-key"),
    # GitHub PAT / fine-grained
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,}\b"),
     "github-token"),
    # Slack webhook
    (re.compile(r"https://hooks\.slack\.com/services/[A-Z0-9]{9}/[A-Z0-9B-Z0-9]{11}/[A-Za-z0-9]{24}"),
     "slack-webhook"),
    # SendGrid
    (re.compile(r"\bSG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{43,}\b"),
     "sendgrid-key"),
    # Generic: api_key = "..."  apikey = "..."  api-key = "..."
    (re.compile(r"""(?i)\bapi[_\-]?key\s*[:=]\s*["`']([A-Za-z0-9\-_/.]{16,80})["`']"""),
     "api-key"),
    # client_secret = "..."
    (re.compile(r"""(?i)client[_\-]?secret\s*[:=]\s*["`']([A-Za-z0-9\-_./+]{16,80})["`']"""),
     "client-secret"),
    # Hardcoded Bearer token in source
    (re.compile(r"""\bBearer\s+([A-Za-z0-9\-._~+/]{20,})\b"""),
     "bearer-token"),
    # PEM private key header
    (re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
     "private-key"),
    # Weak / placeholder secrets — catches common insecure defaults
    (re.compile(
        r"""(?i)(?:secret|password|passwd|pwd|key|token)\s*[=:]\s*['"`]"""
        r"""(your[_\s.-]*secret[_\s.-]*here|changeme|change[_\s.-]*me|"""
        r"""password1?2?3?|secret1?2?3?|letmein|qwerty|abc123|admin1?2?3?|"""
        r"""test1?2?3?|default|placeholder|my[_\s.-]*secret|hardcoded|"""
        r"""example[_\s.-]*secret|dummy|fake|todo|supersecret|verysecret)['"`]"""),
     "weak-placeholder"),
    # Twilio account SID / auth token
    (re.compile(r"\bAC[0-9a-f]{32}\b"),
     "twilio-account-sid"),
    # Generic high-entropy hex strings assigned to secret-like variable names
    (re.compile(r"""(?i)(?:secret|token|key|password|passwd|pwd)\s*[=:]\s*['"`]([0-9a-f]{32,64})['"`]"""),
     "hex-secret"),
    # Mailgun API key
    (re.compile(r"\bkey-[0-9a-zA-Z]{32}\b"),
     "mailgun-key"),
    # Heroku API key pattern
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"),
     "uuid-token"),
    # Firebase API key — specific AIzaSy prefix (subset of google-api-key, different label)
    (re.compile(r'\bAIzaSy[A-Za-z0-9_-]{33}\b'), "firebase-api-key"),
    # SendBird / PubNub SDK keys — UUID-shaped but with context anchor
    (re.compile(r"""(?i)(?:appId|applicationId|app_id)\s*[=:]\s*['"`]([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})['"`]"""), "sendbird-app-id"),
    (re.compile(r'\bpub-c-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b'), "pubnub-publish-key"),
    (re.compile(r'\bsub-c-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b'), "pubnub-subscribe-key"),
    # Mapbox public token (pk.eyJ1... JWT-shaped)
    (re.compile(r'\bpk\.eyJ1[A-Za-z0-9._-]{20,}\b'), "mapbox-public-token"),
    # Note: stripe pk_live/pk_test already covered by the stripe-key pattern above.
]

# Deduplicate a match value: truncate + normalise for use as a set key.
def _secret_key(val):
    return val[:60].lower().strip()


def extract_http_calls_and_secrets(js_clean, output_dir):
    """
    Stage 5c — scan the JS corpus for:
      • HTTP call URLs (fetch / axios / XHR / Angular HttpClient / jQuery ajax)
      • Hardcoded secrets (JWT, AWS, Google, Stripe, GitHub, generic api-key patterns)

    Results are written to http-calls.json and secrets-extended.json (JSONL).
    Returns (http_calls_file, secrets_file) — either may be None if nothing found.
    """
    stage_header("5c", "HTTP call extraction + extended secrets scan")

    http_calls = []         # [{method, url, kind, file, line}]
    secrets    = []         # [{kind, match, file, line}]
    seen_secrets = set()    # deduplicate by (kind, truncated value)

    js_files = sorted(js_clean.glob("*.js"))
    Log.verbose(f"scanning {len(js_files)} JS files")

    for jsfile in js_files:
        try:
            content = jsfile.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        lines = content.splitlines()

        # ── HTTP calls ──
        for pattern, kind in _HTTP_CALL_PATTERNS:
            for m in pattern.finditer(content):
                # Patterns with method in group 1, url in group 2
                if kind in ("axios", "angular-http", "xhr", "node-request",
                            "node-http", "node-got", "superagent", "express-route"):
                    method = m.group(1).upper()
                    url = m.group(2)
                    if kind == "express-route" and method == "ALL":
                        method = "*"
                elif kind == "jquery":
                    method = m.group(1).upper() if m.group(1).lower() != "ajax" else "?"
                    url = m.group(2)
                elif kind == "auth-header":
                    method, url = "HEADER", m.group(1)
                else:
                    # fetch, and fallback
                    method, url = "GET", m.group(1)

                url = url.strip()
                # Skip too-short, data URIs, and protocol-relative
                if len(url) < 2 or url.startswith(("//", "data:", "blob:")):
                    continue
                # For Express routes, also skip middleware mounts that are just "/" or ""
                if kind == "express-route" and url in ("/", ""):
                    continue
                line_no = content[: m.start()].count("\n") + 1
                http_calls.append({
                    "kind":   kind,
                    "method": method,
                    "url":    url[:300],
                    "file":   jsfile.name,
                    "line":   line_no,
                })

        # ── Secrets ──
        # Patterns where a bare regex match isn't enough — require high Shannon
        # entropy to filter out placeholder values, sequential IDs, and test data.
        _ENTROPY_GATED = {"hex-secret", "uuid-token"}
        _ENTROPY_MIN   = 3.5   # bits/char; genuine secrets typically score ≥ 3.8

        for pattern, kind in _SECRET_PATTERNS:
            for m in pattern.finditer(content):
                val = m.group(0)
                # If the pattern has a capturing group, use it (narrows the match)
                try:
                    g = m.group(1)
                    if g:
                        val = g
                except IndexError:
                    pass  # pattern has no groups — use full match (m.group(0))
                val = val.strip()
                if not val or len(val) < 8:
                    continue
                # Entropy gate for high-FP patterns: discard low-entropy strings
                # such as "aabbccdd..." or sequential IDs.
                if kind in _ENTROPY_GATED and _shannon_entropy(val) < _ENTROPY_MIN:
                    continue
                sk = (kind, _secret_key(val))
                if sk in seen_secrets:
                    continue
                seen_secrets.add(sk)
                line_no = content[: m.start()].count("\n") + 1
                # Redact the middle of the value so the report is safe to share
                display = val if len(val) <= 12 else val[:6] + "…" + val[-4:]
                secrets.append({
                    "kind":    kind,
                    "match":   display,
                    "raw_len": len(val),
                    "file":    jsfile.name,
                    "line":    line_no,
                })

    # Write outputs
    http_file = None
    if http_calls:
        http_file = output_dir / "http-calls.json"
        with http_file.open("w") as f:
            for c in http_calls:
                f.write(json.dumps(c) + "\n")
        # Summarise by kind
        by_kind = {}
        for c in http_calls:
            by_kind[c["kind"]] = by_kind.get(c["kind"], 0) + 1
        kind_str = ", ".join(f"{n} {k}" for k, n in sorted(by_kind.items(), key=lambda x: -x[1]))
        Log.info(f"    {C.GREEN}[+]{C.RESET} {len(http_calls)} HTTP call references: {kind_str}")
    else:
        Log.info("    [-] No HTTP call references found")

    secrets_file = None
    if secrets:
        secrets_file = output_dir / "secrets-extended.json"
        with secrets_file.open("w") as f:
            for s in secrets:
                f.write(json.dumps(s) + "\n")
        by_kind = {}
        for s in secrets:
            by_kind[s["kind"]] = by_kind.get(s["kind"], 0) + 1
        kind_str = ", ".join(f"{n} {k}" for k, n in sorted(by_kind.items(), key=lambda x: -x[1]))
        Log.info(f"    {C.YELLOW}[!]{C.RESET} {len(secrets)} secret candidate(s): {kind_str}")
        Log.info(f"    {C.DIM}↳ Values truncated in output — inspect raw JS for full value{C.RESET}")
    else:
        Log.info("    [-] No extended secret patterns matched")

    return http_file, secrets_file


# ---------- Stage 6: Semgrep ----------

# Local rules that catch DOM sinks in both standard JS and Angular compiled output.
# Angular compiles [innerHTML]="x" into runtime calls like h("innerHTML", x, sanitizer),
# which AST-based pattern-matching rules never see as property assignments.
# pattern-regex rules match raw text and catch both forms.
#
# YAML note: all pattern-regex values use single-quoted YAML strings. Never include a
# literal single-quote character inside those strings — use ["] or omit it instead.
_SEMGREP_LOCAL_RULES = """\
rules:
  - id: local-innerhtml-direct
    pattern: $X.innerHTML = $Y
    message: Direct innerHTML assignment - potential DOM XSS
    languages: [javascript]
    severity: WARNING
  - id: local-outerhtml-direct
    pattern: $X.outerHTML = $Y
    message: Direct outerHTML assignment - potential DOM XSS
    languages: [javascript]
    severity: WARNING
  - id: local-eval-call
    pattern: eval($X)
    message: eval() call - potential code injection
    languages: [javascript]
    severity: ERROR
  - id: local-document-write
    pattern: document.write($X)
    message: document.write() call - potential DOM XSS
    languages: [javascript]
    severity: WARNING
  - id: local-insert-adjacent-html
    pattern: $X.insertAdjacentHTML($POS, $Y)
    message: insertAdjacentHTML() call - potential DOM XSS
    languages: [javascript]
    severity: WARNING
  - id: local-angular-innerhtml-call
    pattern-regex: '(?:innerhtml|innerHTML).*sanitize|h\\("innerHTML"'
    message: Angular [innerHTML] binding in compiled template - verify DomSanitizer is not bypassed
    languages: [javascript]
    severity: WARNING
  - id: local-innerhtml-assign-regex
    pattern-regex: '\\.innerHTML\\s*='
    message: innerHTML assignment (regex fallback)
    languages: [javascript]
    severity: WARNING
  - id: local-outerhtml-assign-regex
    pattern-regex: '\\.outerHTML\\s*='
    message: outerHTML assignment (regex fallback)
    languages: [javascript]
    severity: WARNING
  - id: local-document-write-regex
    pattern-regex: 'document\\.write\\s*\\('
    message: document.write() call (regex fallback)
    languages: [javascript]
    severity: WARNING
  - id: local-eval-regex
    # Require that `eval` is NOT preceded by `.`, `[`, `$`, or word chars — i.e.
    # only flag the global `eval(` invocation, not method calls like
    # `obj.eval(`, `window.eval(`, `foo[eval](`, etc. which are unrelated.
    pattern-regex: '(?<![.\\w$\\[])eval\\s*\\('
    message: eval() call (regex fallback)
    languages: [javascript]
    severity: ERROR
  - id: local-set-attr-event
    pattern-regex: '\\.setAttribute\\s*\\(\\s*"on\\w+'
    message: setAttribute with event handler attribute
    languages: [javascript]
    severity: WARNING

  # ── NoSQL Injection ───────────────────────────────────────────────────────────
  - id: local-nosql-where-taint
    pattern-regex: '\\$where\\s*:\\s*`[^`]*\\$\\{'
    message: >
      MongoDB $where with template literal - possible NoSQL JS injection if
      request data reaches this query. Never pass user input into $where.
    languages: [javascript]
    severity: ERROR

  - id: local-nosql-findone-req
    pattern-regex: '\\.(?:findOne|find|findById|findByIdAndUpdate|findOneAndUpdate|updateOne|deleteOne)\\s*\\([^)]*(?:req|request)\\.(?:body|query|params)'
    message: >
      Possible NoSQL injection - request input directly used in MongoDB query
      method. Sanitize inputs and use mongoose schema validation.
    languages: [javascript]
    severity: ERROR

  # ── Hardcoded JWT Secret ──────────────────────────────────────────────────────
  - id: local-jwt-hardcoded-sign
    patterns:
      - pattern-either:
          - pattern: $JWT.sign($PAYLOAD, "...", ...)
          - pattern: $JWT.sign($PAYLOAD, '...', ...)
    message: >
      Hardcoded JWT secret string literal in jwt.sign(). Store secrets in
      environment variables (process.env.JWT_SECRET) and never commit to source.
    languages: [javascript]
    severity: ERROR

  - id: local-jwt-hardcoded-verify
    patterns:
      - pattern-either:
          - pattern: $JWT.verify($TOKEN, "...", ...)
          - pattern: $JWT.verify($TOKEN, '...', ...)
    message: >
      Hardcoded JWT secret string literal in jwt.verify(). Store secrets in
      environment variables and never commit to source control.
    languages: [javascript]
    severity: ERROR

  - id: local-jwt-none-algorithm
    pattern-regex: '"algorithm"\\s*:\\s*"none"|algorithm.*:\\s*none|algorithms.*:\\s*\\[.*none'
    message: >
      JWT "none" algorithm disables signature verification entirely.
      Always require HS256/RS256 and reject unsigned tokens.
    languages: [javascript]
    severity: ERROR

  # ── OS Command Injection ──────────────────────────────────────────────────────
  - id: local-command-injection-req
    pattern-regex: '(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\\s*\\([^)]*(?:req|request)\\.(?:body|query|params)'
    message: >
      Possible OS command injection - request input used in child_process
      function. Never pass user input to command execution functions.
    languages: [javascript]
    severity: ERROR

  - id: local-command-injection-template
    pattern-regex: '(?:exec|execSync|spawn|spawnSync)\\s*\\(`[^`]*\\$\\{'
    message: >
      Template literal in command execution function. Verify no user input
      reaches this code path (OS command injection risk).
    languages: [javascript]
    severity: WARNING

  # ── Path Traversal ────────────────────────────────────────────────────────────
  - id: local-path-traversal-req
    pattern-regex: '(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|appendFile|appendFileSync|res\\.download|res\\.sendFile|res\\.sendfile)\\s*\\([^)]*(?:req|request)\\.(?:body|query|params)'
    message: >
      Possible path traversal - request input used in file system or file-serving
      operation. Use path.resolve() and verify the resolved path stays within the
      allowed base directory.
    languages: [javascript]
    severity: ERROR

  - id: local-path-traversal-template
    pattern-regex: '(?:readFile|readFileSync|createReadStream)\\s*\\(`[^`]*\\$\\{'
    message: >
      Template literal in file read operation. Verify no user input can reach
      here (path traversal risk).
    languages: [javascript]
    severity: WARNING

  # ── Weak Cryptography ─────────────────────────────────────────────────────────
  - id: local-weak-hash-md5
    pattern: $CRYPTO.createHash("md5")
    message: >
      MD5 is a weak hash with known collisions. Use SHA-256 or SHA-3 instead.
    languages: [javascript]
    severity: WARNING

  - id: local-weak-hash-sha1
    pattern: $CRYPTO.createHash("sha1")
    message: >
      SHA-1 is deprecated with known weaknesses. Use SHA-256 or SHA-3 instead.
    languages: [javascript]
    severity: WARNING

  - id: local-insecure-random
    patterns:
      - pattern: $VAR = <... Math.random() ...>
      - metavariable-regex:
          metavariable: $VAR
          regex: (?i).*(token|secret|password|passwd|key|salt|nonce|seed|auth|csrf|session|otp).*
    message: >
      Math.random() is not cryptographically secure and must not be used to
      generate tokens, keys, passwords, or nonces. Use crypto.randomBytes()
      (Node.js) or crypto.getRandomValues() (browser) instead.
    languages: [javascript]
    severity: WARNING

  - id: local-aes-ecb-mode
    pattern-regex: 'createCipheriv\\s*\\(\\s*"aes-\\d+-ecb"'
    message: >
      AES-ECB mode is deterministic and insecure for repeated or structured
      data. Use AES-GCM or AES-CBC with a random IV.
    languages: [javascript]
    severity: ERROR

  # ── SSRF ──────────────────────────────────────────────────────────────────────
  - id: local-ssrf-fetch-req
    pattern-regex: '\\bfetch\\s*\\(\\s*(?:req|request)\\.'
    message: >
      Possible SSRF - request input used as URL in fetch(). Validate and
      whitelist allowed hosts before making server-side HTTP requests.
    languages: [javascript]
    severity: ERROR

  - id: local-ssrf-axios-req
    pattern-regex: '\\baxios\\.\\w+\\s*\\(\\s*(?:req|request)\\.'
    message: >
      Possible SSRF - request input used as URL in axios call. Validate and
      whitelist allowed hosts before making server-side HTTP requests.
    languages: [javascript]
    severity: ERROR

  - id: local-ssrf-got-req
    pattern-regex: '\\bgot\\.\\w+\\s*\\(\\s*(?:req|request)\\.'
    message: >
      Possible SSRF - request input used as URL in got() call. Validate and
      whitelist allowed hosts before making server-side HTTP requests.
    languages: [javascript]
    severity: ERROR

  # ── CORS Misconfiguration ─────────────────────────────────────────────────────
  - id: local-cors-wildcard
    pattern-regex: '(?i)access-control-allow-origin[^\\n]{0,80}\\*'
    message: >
      CORS wildcard (*) allows any origin to make cross-origin requests.
      Restrict to specific trusted origins in production environments.
    languages: [javascript]
    severity: WARNING

  - id: local-cors-reflect-origin
    pattern-regex: 'Access-Control-Allow-Origin.*(?:req\\.headers\\.origin|req\\.get\\s*\\([^)]*origin)'
    message: >
      Reflected Origin in CORS header without whitelist - any site can make
      credentialed cross-origin requests to this endpoint.
    languages: [javascript]
    severity: ERROR

  # ── Prototype Pollution ───────────────────────────────────────────────────────
  - id: local-proto-pollution
    pattern-regex: '__proto__\\s*\\]|\\["__proto__"\\]|\\.constructor\\.prototype'
    message: >
      Possible prototype pollution - __proto__ or constructor.prototype access
      detected. Sanitize object merge operations with hasOwnProperty checks.
    languages: [javascript]
    severity: ERROR

  - id: local-proto-pollution-merge
    pattern-regex: '(?:Object\\.assign|_\\.merge|_\\.extend|_\\.defaultsDeep|lodash\\.merge|deepmerge|merge)\\s*\\([^,)]+,\\s*(?:req|request)\\.'
    message: >
      Possible prototype pollution - object merge/assign with request input.
      Guard against __proto__, constructor, and prototype keys before merging
      user-supplied objects (CVE-2019-10744 class).
    languages: [javascript]
    severity: WARNING

  # ── Hardcoded Secrets by Variable Name ───────────────────────────────────────
  - id: local-hardcoded-password-var
    patterns:
      - pattern-either:
          - pattern: $VAR = "..."
          - pattern: $VAR = '...'
      - metavariable-regex:
          metavariable: $VAR
          regex: (?i).*(password|passwd|pwd).*
    message: >
      Possible hardcoded password in variable. Use environment variables
      (process.env.*) and never commit credentials to source control.
    languages: [javascript]
    severity: WARNING

  - id: local-hardcoded-secret-var
    patterns:
      - pattern-either:
          - pattern: $VAR = "..."
          - pattern: $VAR = '...'
      - metavariable-regex:
          metavariable: $VAR
          regex: (?i).*(secret|api_key|apikey|private_key|access_key).*
    message: >
      Possible hardcoded secret in variable. Use environment variables and
      never commit secrets to source control.
    languages: [javascript]
    severity: WARNING

  # ── Open Redirect ─────────────────────────────────────────────────────────────
  - id: local-open-redirect
    pattern-regex: 'res\\.redirect\\s*\\([^)]*(?:req|request)\\.(?:body|query|params)'
    message: >
      Possible open redirect - request input used in redirect without
      validation. Whitelist allowed redirect destinations.
    languages: [javascript]
    severity: ERROR

  # ── SQL Injection ─────────────────────────────────────────────────────────────
  - id: local-sqli-template-literal
    pattern-regex: '(?:query|execute|run)\\s*\\(`[^`]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION)[^`]*\\$\\{'
    message: >
      Possible SQL injection - template literal used to construct SQL query.
      Use parameterized queries or prepared statements instead.
    languages: [javascript]
    severity: ERROR

  - id: local-sqli-concatenation
    pattern-regex: '(?:query|execute|run)\\s*\\([^)]*(?:SELECT|INSERT|UPDATE|DELETE)[^)]*\\+\\s*(?:req|request)\\.'
    message: >
      Possible SQL injection - string concatenation to build SQL with request
      input. Use parameterized queries or prepared statements instead.
    languages: [javascript]
    severity: ERROR

  # ── Reflected XSS via response ────────────────────────────────────────────────
  - id: local-reflected-xss-send
    pattern-regex: 'res\\.(?:send|write)\\s*\\([^)]*(?:req|request)\\.(?:body|query|params)'
    message: >
      Possible reflected XSS - request input sent directly in response without
      encoding. Sanitize output before rendering in HTML responses.
    languages: [javascript]
    severity: ERROR

  # ── Unsafe Deserialization ────────────────────────────────────────────────────
  - id: local-unsafe-deserialize
    pattern-regex: '(?:serialize|node-serialize)\\.unserialize\\s*\\(|unserialize\\s*\\(\\s*(?:req|request)\\.'
    message: >
      Unsafe deserialization of user input - possible remote code execution.
      Never deserialize untrusted data with node-serialize or similar libraries.
    languages: [javascript]
    severity: ERROR

  # ── XML External Entity (XXE) ────────────────────────────────────────────────
  - id: local-xxe-noent
    pattern-regex: '(?:parseXml|parseXmlString|parseString|parse)\\s*\\([^,)]+,\\s*\\{[^}]*noent\\s*:\\s*true'
    message: >
      XML parser called with noent:true - external entity processing enabled.
      Remove noent/resolveEntities options or use a safe parser configuration
      to prevent XXE attacks (file read, SSRF, DoS).
    languages: [javascript]
    severity: ERROR

  - id: local-xxe-resolve-entities
    pattern-regex: 'resolveExternalEntities\\s*:\\s*true|allowDtd\\s*:\\s*true|dtdload\\s*:\\s*true'
    message: >
      XML parser option enables external entity or DTD loading. This allows
      XXE attacks that can read local files or perform server-side request forgery.
      Disable external entity resolution in all XML parsers handling untrusted input.
    languages: [javascript]
    severity: ERROR

  # ── RegEx Denial of Service (ReDoS) ──────────────────────────────────────────
  - id: local-redos-pattern
    pattern-regex: 'new RegExp\\(\\s*(?:req|request)\\.'
    message: >
      User input used to construct RegExp - possible ReDoS if input contains
      catastrophic backtracking patterns. Validate input before regex construction.
    languages: [javascript]
    severity: WARNING

  # ── Eval Equivalents (missed by basic eval rule) ──────────────────────────────
  - id: local-settimeout-string
    pattern-regex: '\\bsetTimeout\\s*\\(\\s*(?:"[^"]{0,200}"|`[^`]{0,200}`)'
    message: >
      setTimeout() called with a string argument - equivalent to eval().
      Pass a function reference instead of a string to avoid code injection.
    languages: [javascript]
    severity: ERROR

  - id: local-setinterval-string
    pattern-regex: '\\bsetInterval\\s*\\(\\s*(?:"[^"]{0,200}"|`[^`]{0,200}`)'
    message: >
      setInterval() called with a string argument - equivalent to eval().
      Pass a function reference instead of a string to avoid code injection.
    languages: [javascript]
    severity: ERROR

  - id: local-new-function-constructor
    pattern-regex: 'new\\s+Function\\s*\\('
    message: >
      new Function() constructor dynamically compiles code from a string -
      functionally equivalent to eval(). Avoid or ensure the argument is
      never derived from user input.
    languages: [javascript]
    severity: ERROR

  # ── DOM-Based XSS Sources → Sinks ────────────────────────────────────────────
  - id: local-dom-xss-location-hash
    pattern-regex: '(?:innerHTML|outerHTML|document\\.write)\\s*[=(].*location\\.(?:hash|search|href|pathname)'
    message: >
      DOM XSS - location.hash/search/href used directly in HTML sink.
      Sanitize URL-derived values before writing to the DOM.
    languages: [javascript]
    severity: ERROR

  - id: local-dom-xss-referrer
    pattern-regex: '(?:innerHTML|outerHTML|document\\.write)\\s*[=(].*document\\.referrer'
    message: >
      DOM XSS - document.referrer used in HTML sink without sanitization.
      An attacker controls the Referer header and can inject HTML/JS.
    languages: [javascript]
    severity: ERROR

  - id: local-dom-open-redirect
    pattern-regex: '(?:location\\.href|location\\.replace|location\\.assign)\\s*=\\s*.*(?:location\\.(?:hash|search)|getParameter|URLSearchParams)'
    message: >
      DOM-based open redirect - URL parameter used to set window location
      without validation. An attacker can redirect users to arbitrary URLs.
    languages: [javascript]
    severity: ERROR

  # ── postMessage Without Origin Check ─────────────────────────────────────────
  - id: local-postmessage-wildcard
    pattern-regex: '\\.postMessage\\s*\\([^,]+,\\s*"\\*"'
    message: >
      postMessage() with wildcard target origin (*) sends data to any window.
      Specify the exact target origin to prevent data leakage to malicious frames.
    languages: [javascript]
    severity: WARNING

  # ── Sensitive Data in Client Storage ─────────────────────────────────────────
  - id: local-localstorage-sensitive
    pattern-regex: '(?:localStorage|sessionStorage)\\.setItem\\s*\\([^,]*(?i:token|secret|password|passwd|auth|jwt|apikey|api_key|credential)'
    message: >
      Sensitive data (token/password/key) stored in localStorage or sessionStorage.
      This data is accessible to any JS on the page and persists after tab close.
      Use httpOnly cookies for session tokens instead.
    languages: [javascript]
    severity: WARNING

  # ── document.domain Relaxation ───────────────────────────────────────────────
  - id: local-document-domain
    pattern-regex: 'document\\.domain\\s*='
    message: >
      document.domain assignment relaxes the Same-Origin Policy. This can allow
      sibling subdomains to read each other''s DOM and cookies. Avoid unless
      strictly necessary, and ensure all subdomains are equally trusted.
    languages: [javascript]
    severity: WARNING

  # ── Client-Side Template Injection ───────────────────────────────────────────
  - id: local-vue-v-html
    pattern-regex: 'v-html\\s*='
    message: >
      Vue v-html directive renders raw HTML and is a DOM XSS sink.
      Never bind v-html to user-controlled data; use text interpolation instead.
    languages: [javascript]
    severity: WARNING

  - id: local-angular-trust-html
    pattern-regex: 'bypassSecurityTrustHtml|bypassSecurityTrustScript|bypassSecurityTrustResourceUrl|\\$sce\\.trustAsHtml'
    message: >
      Angular DomSanitizer bypass or AngularJS $sce.trustAsHtml detected.
      This explicitly disables XSS protection - ensure the input is truly safe
      and cannot contain user-controlled content.
    languages: [javascript]
    severity: ERROR

  - id: local-react-dangerous-html
    pattern-regex: 'dangerouslySetInnerHTML\\s*=\\s*\\{\\{\\s*__html\\s*:'
    message: >
      React dangerouslySetInnerHTML renders raw HTML, bypassing React''s XSS
      protection. Ensure the __html value is sanitized (DOMPurify) and never
      contains user-controlled content.
    languages: [javascript]
    severity: WARNING

  # ── window.name as XSS source ────────────────────────────────────────────────
  # window.name persists across navigations and is writable by any page that
  # opens this page in a new tab — making it a cross-origin taint source.
  - id: local-dom-xss-window-name
    pattern-regex: '(?:innerHTML|outerHTML|document\\.write|eval|setTimeout|setInterval)\\s*[=(].*window\\.name'
    message: >
      window.name is cross-origin persistent — any opener page can set it to an
      arbitrary string before navigating here. Using it in HTML sinks or eval()
      is a direct DOM XSS vector. Validate or sanitize window.name before use.
    languages: [javascript]
    severity: ERROR

  # ── postMessage origin check bypass ──────────────────────────────────────────
  # indexOf / match / includes / startsWith instead of strict === allows
  # an attacker to register trusted.com.evil.com and pass the check.
  # (HackerOne #209008 — Uber, #398054 — HackerOne.com itself)
  - id: local-postmessage-origin-bypass
    pattern-regex: 'event\\.origin\\.(?:indexOf|includes|match|startsWith|endsWith)\\s*\\(|e\\.origin\\.(?:indexOf|includes|match|startsWith|endsWith)\\s*\\('
    message: >
      Weak postMessage origin check using indexOf/match/includes instead of strict
      equality (===). Attackers bypass this by registering a domain that contains
      the trusted string as a substring (e.g. trusted.com.evil.com passes an
      indexOf("trusted.com") check). Use === with a hardcoded origin string.
    languages: [javascript]
    severity: ERROR

  # ── postMessage data used as redirect target ──────────────────────────────────
  - id: local-postmessage-data-redirect
    pattern-regex: 'addEventListener\\s*\\(\\s*"message"[^}]{0,400}(?:location\\.href|location\\.replace|location\\.assign)\\s*='
    message: >
      postMessage handler sets window.location — verify event.origin is strictly
      validated before trusting event.data as a URL. Attackers can redirect the
      user to javascript: URLs or phishing sites via a cross-origin message.
    languages: [javascript]
    severity: ERROR

  # ── jQuery deep extend — prototype pollution (CVE-2019-11358) ────────────────
  - id: local-jquery-extend-deep
    pattern-regex: '\\$\\.extend\\s*\\(\\s*true\\s*,'
    message: >
      jQuery.extend() in deep mode (first argument true) is vulnerable to prototype
      pollution (CVE-2019-11358) when the source object contains __proto__ or
      constructor keys. Upgrade to jQuery >= 3.4.0 and sanitize merge inputs.
    languages: [javascript]
    severity: WARNING

  # ── jQuery parseHTML with non-literal input ───────────────────────────────────
  - id: local-jquery-parsehtml-var
    patterns:
      - pattern: $.parseHTML($INPUT)
      - pattern-not: $.parseHTML("...")
      - pattern-not: $.parseHTML('...')
    message: >
      $.parseHTML() with a non-literal string argument creates DOM XSS risk.
      In jQuery < 3.0 it also executes inline scripts. Sanitize input with
      DOMPurify.sanitize() before passing it to $.parseHTML().
    languages: [javascript]
    severity: WARNING

  # ── OAuth access_token extracted from URL fragment ────────────────────────────
  # Implicit flow delivers tokens in location.hash — accessible to all JS on
  # the page, visible in browser history, and potentially leaked via Referer.
  - id: local-oauth-token-in-hash
    pattern-regex: 'location\\.hash[^;\\n]{0,120}access_token|access_token[^;\\n]{0,120}location\\.hash'
    message: >
      OAuth access_token extracted from URL fragment (location.hash). Implicit
      flow tokens in the hash are accessible to any script on the page, appear in
      browser history, and can leak via Referer to third-party resources. Use
      authorization code flow with PKCE instead.
    languages: [javascript]
    severity: WARNING

  # ── window.opener manipulation (reverse tabnapping) ──────────────────────────
  - id: local-window-opener-set-location
    pattern-regex: 'window\\.opener\\s*&&\\s*window\\.opener\\.location|window\\.opener\\.location\\s*='
    message: >
      window.opener.location assignment detected. Pages opened via target="_blank"
      links without rel="noopener" can have their opener redirected by the child
      page — enabling phishing (reverse tabnapping). Always add rel="noopener
      noreferrer" to outbound target="_blank" links.
    languages: [javascript]
    severity: WARNING

  # ── target="_blank" without rel="noopener" ───────────────────────────────────
  - id: local-target-blank-no-opener
    pattern-regex: 'target\\s*=\\s*(?:"_blank"|''_blank''|`_blank`)(?!.*(?:noopener|noreferrer))'
    message: >
      target="_blank" link without rel="noopener noreferrer". The opened page can
      access window.opener and redirect the parent tab (reverse tabnapping). Add
      rel="noopener noreferrer" to all outbound _blank links.
    languages: [javascript]
    severity: WARNING

  # ── JSONP dynamic script injection ───────────────────────────────────────────
  - id: local-jsonp-callback-injection
    pattern-regex: 'script\\.src\\s*=[^;\\n]*[?&]callback='
    message: >
      Dynamic JSONP script injection with a callback parameter. If the callback
      name is user-controlled, an attacker can set it to any reachable function
      (e.g. eval) and execute arbitrary code via cross-site script inclusion.
      Validate callback against a strict allowlist of function names.
    languages: [javascript]
    severity: WARNING

  # ── Authentication token appended to URL query string ────────────────────────
  - id: local-token-in-querystring
    pattern-regex: '(?:location\\.href|location\\.search|window\\.location)\\s*[+= ][^;\\n]*(?:token|access_token|id_token|jwt|api_key|session_id)\\s*[=+]'
    message: >
      Authentication token appended to URL query string. Query parameters are
      recorded in server logs, browser history, and Referer headers sent to
      third-party resources loaded on subsequent pages. Pass tokens in
      Authorization headers or POST body instead.
    languages: [javascript]
    severity: WARNING

  # ── eval / setTimeout / setInterval with DOM sources ─────────────────────────
  - id: local-eval-dom-source
    pattern-regex: '\\beval\\s*\\([^)]*(?:location\\.(?:hash|search|href)|window\\.name|document\\.referrer)|\\bsetTimeout\\s*\\([^,)]*(?:location\\.(?:hash|search)|window\\.name)|\\bsetInterval\\s*\\([^,)]*(?:location\\.(?:hash|search)|window\\.name)'
    message: >
      eval() / setTimeout() / setInterval() called with data from a DOM source
      (location.hash, location.search, window.name). These sources are
      attacker-controlled and this is a direct DOM XSS / code injection sink.
    languages: [javascript]
    severity: ERROR

  # ── EJS template injection via res.render passing req.* as options ────────────
  - id: local-ejs-render-req-options
    patterns:
      - pattern: res.render($VIEW, req.$PROP)
      - metavariable-regex:
          metavariable: $PROP
          regex: ^(body|query|params)$
    message: >
      res.render() called with req.body/query/params as the options object.
      EJS (CVE-2022-29078) allows RCE via the outputFunctionName option — an
      attacker can inject arbitrary code by setting
      ?settings[view options][outputFunctionName]=x;payload;s.
      Only pass sanitized/explicit properties to res.render().
    languages: [javascript]
    severity: ERROR

  # ── Electron: shell.openExternal without protocol whitelist ──────────────────
  - id: local-electron-open-external
    patterns:
      - pattern: shell.openExternal($URL)
      - pattern-not: shell.openExternal("...")
      - pattern-not: shell.openExternal('...')
    message: >
      shell.openExternal() called with a variable URL. Without a strict protocol
      check (https?:// only), attackers can trigger custom OS protocols
      (ms-msdt:, search-ms:, smb://, file://) via a crafted link, achieving
      1-click RCE on the victim''s machine.
    languages: [javascript]
    severity: ERROR

  # ── Electron: insecure BrowserWindow webPreferences ──────────────────────────
  - id: local-electron-node-integration
    pattern-regex: 'nodeIntegration\\s*:\\s*true'
    message: >
      nodeIntegration: true in Electron BrowserWindow enables require() in the
      renderer process. Any XSS in the renderer becomes full Node.js RCE.
      Set nodeIntegration: false and use a contextBridge preload instead.
    languages: [javascript]
    severity: ERROR

  - id: local-electron-context-isolation-off
    pattern-regex: 'contextIsolation\\s*:\\s*false'
    message: >
      contextIsolation: false in Electron BrowserWindow removes the security
      boundary between the preload script and the renderer page. Combined with
      any XSS this allows access to Node.js APIs. Set contextIsolation: true.
    languages: [javascript]
    severity: ERROR

  - id: local-electron-web-security-off
    pattern-regex: 'webSecurity\\s*:\\s*false'
    message: >
      webSecurity: false in Electron BrowserWindow disables the same-origin
      policy and allows loading local files from web content — severe security
      regression. Remove this option or restrict it to development only.
    languages: [javascript]
    severity: ERROR

  # ── WebSocket onmessage data flowing into DOM sink ───────────────────────────
  - id: local-websocket-msg-to-dom
    pattern-regex: '(?:\\.onmessage\\s*=|addEventListener\\s*\\(\\s*(?:"message"|''message'')\\s*,[^)]*\\))[^}]*(?:innerHTML|outerHTML|document\\.write|insertAdjacentHTML)\\s*[=(]'
    message: >
      WebSocket onmessage handler appears to route incoming data into a DOM
      sink (innerHTML, outerHTML, document.write, insertAdjacentHTML). WebSocket
      messages from a server that processes user input are attacker-controlled —
      sanitize with DOMPurify before inserting into the DOM.
    languages: [javascript]
    severity: WARNING

  # ── ReactMarkdown / marked unsafe rendering options ──────────────────────────
  - id: local-react-markdown-escape-html
    pattern-regex: 'escapeHtml\\s*=\\s*\\{?\\s*false\\s*\\}?'
    message: >
      ReactMarkdown rendered with escapeHtml={false} allows raw HTML tags in
      user-supplied markdown to execute as DOM elements — enabling XSS. Remove
      this prop or sanitize content with rehype-sanitize.
    languages: [javascript]
    severity: ERROR

  - id: local-marked-sanitize-false
    pattern-regex: 'marked\\s*\\([^,)]+,\\s*\\{[^}]*sanitize\\s*:\\s*false'
    message: >
      marked() called with sanitize: false. This option was deprecated because
      it disables HTML sanitization, allowing user-supplied markdown to inject
      script tags. Use DOMPurify on the output or a safe renderer.
    languages: [javascript]
    severity: ERROR

  - id: local-remark-html-dangerous
    pattern-regex: 'remarkHtml\\s*\\(\\s*\\{[^}]*allowDangerousHtml\\s*:\\s*true'
    message: >
      remark-html configured with allowDangerousHtml: true passes raw HTML from
      the markdown source to the DOM output — XSS via user-controlled markdown.
      Remove this option or sanitize the output.
    languages: [javascript]
    severity: ERROR

  # ── Cypher injection: Neo4j session.run with template literal ─────────────────
  - id: local-cypher-injection-template
    pattern-regex: '(?:session|txc|tx)\\.run\\s*\\(`[^`]*\\$\\{(?:req|request)\\.'
    message: >
      Neo4j session.run() called with a template literal that interpolates
      request parameters — Cypher injection. An attacker can escape the query
      and enumerate or modify graph data. Use parameterized queries:
      session.run(''MATCH (u:User {name: $n})'', { n: req.body.name }).
    languages: [javascript]
    severity: ERROR

  - id: local-cypher-injection-concat
    pattern-regex: '(?:session|txc|tx)\\.run\\s*\\([^`]*\\+\\s*(?:req|request)\\.'
    message: >
      Neo4j session.run() called with string concatenation from request
      parameters — Cypher injection. Use parameterized queries instead of
      string concatenation.
    languages: [javascript]
    severity: ERROR

  # ── GraphQL: introspection / GraphiQL enabled in production ──────────────────
  - id: local-graphql-introspection-on
    pattern-regex: 'introspection\\s*:\\s*true'
    message: >
      GraphQL introspection explicitly enabled. In production this exposes the
      complete schema to unauthenticated attackers, revealing hidden fields,
      mutations, and data types. Disable with introspection: false and use
      schema-stitching tools for development access.
    languages: [javascript]
    severity: WARNING

  - id: local-graphql-graphiql-on
    pattern-regex: 'graphiql\\s*:\\s*true'
    message: >
      GraphiQL IDE enabled. If this route is reachable without authentication
      in production it exposes the full GraphQL schema and allows arbitrary
      query execution. Gate this behind auth middleware or disable in production.
    languages: [javascript]
    severity: WARNING

  # ── Cookie value reflected into script tag ───────────────────────────────────
  - id: local-cookie-in-script
    pattern-regex: 'res\\.(?:send|write)\\s*\\(`[^`]*<script[^`]*\\$\\{[^}]*req\\.cookies\\.'
    message: >
      req.cookies value interpolated into a <script> block in the HTTP response.
      A cookie value can be attacker-controlled (set via subdomain, MITM, or
      prior injection). Encode with encodeURIComponent() or JSON.stringify()
      before embedding in a script context.
    languages: [javascript]
    severity: ERROR

  # ── Client-side path traversal: URLSearchParams/location into fetch URL ──────
  - id: local-client-path-traversal
    pattern-regex: '(?:fetch|axios\\.(?:get|post|put|patch|delete))\\s*\\(`[^`]*\\$\\{[^}]*(?:URLSearchParams|location\\.(?:search|hash|pathname))'
    message: >
      fetch() / axios call URL built from URLSearchParams or location.*. An
      attacker can inject ../ sequences to traverse to unintended API endpoints
      (client-side path traversal). Normalize the value with
      encodeURIComponent() or strip traversal sequences before use.
    languages: [javascript]
    severity: WARNING

  # ── atob() + JSON.parse() flowing into DOM sink ──────────────────────────────
  - id: local-atob-json-to-dom
    pattern-regex: '(?:JSON\\.parse\\s*\\(\\s*atob|atob\\s*\\([^)]+\\)[^;]*JSON\\.parse)'
    message: >
      atob() + JSON.parse() used to decode URL-supplied data. If the decoded
      result is inserted into innerHTML or dangerouslySetInnerHTML without
      sanitization, a crafted base64 payload enables XSS. Validate the decoded
      structure and sanitize before DOM insertion.
    languages: [javascript]
    severity: WARNING

  # ── OAuth redirect_uri validated with startsWith / includes ──────────────────
  - id: local-oauth-redirect-uri-partial
    pattern-regex: 'redirect_uri\\s*\\.\\s*(?:startsWith|includes)\\s*\\('
    message: >
      redirect_uri validated with .startsWith() or .includes() instead of
      strict equality against an allowlist. Attackers can bypass prefix checks
      using path traversal (https://allowed.com/../../../other) or subdomain
      tricks. Use strict === comparison against a known-good URL list.
    languages: [javascript]
    severity: ERROR

  # ── WebSocket server: missing Origin validation ───────────────────────────────
  - id: local-websocket-no-origin
    pattern-regex: 'new\\s+WebSocket\\.Server\\s*\\(\\s*\\{[^}]*port\\s*:'
    message: >
      WebSocket.Server created with a port option but no verifyClient callback.
      Without origin validation any web page can initiate a WebSocket connection
      using the victim''s cookies (Cross-Site WebSocket Hijacking). Add
      verifyClient: (info) => allowedOrigins.includes(info.origin).
    languages: [javascript]
    severity: WARNING

  # ── AngularJS $compile / $eval / $parse with user input ──────────────────────
  - id: local-angularjs-compile-req
    pattern-regex: '\\$compile\\s*\\(\\s*(?:req|request)\\.'
    message: >
      $compile() called with request data. AngularJS template compilation of
      user input enables sandbox escape and XSS via
      {{constructor.constructor(''alert(1)'')()}}. Never compile user-supplied
      strings as Angular templates.
    languages: [javascript]
    severity: ERROR

  - id: local-angularjs-eval-req
    pattern-regex: '\\$(?:scope\\.)?\\$eval\\s*\\(\\s*(?:req|request)\\.'
    message: >
      $scope.$eval() called with request data — AngularJS expression injection.
      User-controlled expressions execute in the Angular scope and can access
      the window object. Pass only trusted expressions to $eval.
    languages: [javascript]
    severity: ERROR

  # ── CORS: reflected origin + Allow-Credentials without allowlist ──────────────
  - id: local-cors-credentials-reflect
    pattern-regex: 'Access-Control-Allow-Credentials[^\\n]{0,10}true[^\\n]{0,300}Access-Control-Allow-Origin[^\\n]*(?:req\\.headers\\.origin|req\\.get\\s*\\([^)]*origin)|Access-Control-Allow-Origin[^\\n]*(?:req\\.headers\\.origin|req\\.get\\s*\\([^)]*origin)[^\\n]{0,300}Access-Control-Allow-Credentials[^\\n]{0,10}true'
    message: >
      Access-Control-Allow-Credentials: true set alongside a reflected
      Access-Control-Allow-Origin (from req.headers.origin) without an explicit
      allowlist check. This gives any origin credentialed cross-domain access —
      equivalent to CORS wildcard with credentials. Validate the origin against
      a strict allowlist before reflecting it.
    languages: [javascript]
    severity: ERROR
"""


def run_semgrep(target_dir, output_dir, available_tools):
    stage_header(6, "Semgrep (SAST)")
    if not available_tools.get("semgrep"):
        Log.info("    [-] semgrep not installed, skipping")
        return None

    semgrep_json = output_dir / "semgrep.json"

    # Write local fallback rules — catches Angular compiled patterns that registry
    # rules miss because they look for AST-level property assignments, not function calls.
    local_rules = output_dir / ".semgrep-local.yaml"
    local_rules.write_text(_SEMGREP_LOCAL_RULES, encoding="utf-8")

    cmd = [
        "semgrep",
        "--config=p/javascript",
        "--config=p/xss",
        "--config=p/owasp-top-ten",
        "--config=p/react",
        "--config=p/nodejs",
        f"--config={local_rules}",
        "--exclude=*.min.js",
        "--severity=ERROR",
        "--severity=WARNING",
        "--json",
        "--output", str(semgrep_json),
        "--quiet",
        "--timeout", str(SEMGREP_RULE_TIMEOUT),
        "--timeout-threshold", str(SEMGREP_TIMEOUT_THRESHOLD),
        str(target_dir),
    ]
    run(cmd, check=False, quiet=True, timeout=SEMGREP_OVERALL_TIMEOUT)

    if not semgrep_json.exists():
        Log.warn("Semgrep produced no output — check rule-pack connectivity or run with -v")
        return None

    try:
        data = json.loads(semgrep_json.read_text(encoding="utf-8", errors="replace"))
        findings = data.get("results", [])
        errors = data.get("errors", [])

        # Count timeouts separately — they mean 0 results for that rule on that file,
        # not that the code is clean.
        timeouts = [e for e in errors if e.get("type") == "Timeout"]
        other_errors = [e for e in errors if e.get("type") != "Timeout"]

        error_count = sum(1 for r in findings if r.get("extra", {}).get("severity") == "ERROR")
        warning_count = sum(1 for r in findings if r.get("extra", {}).get("severity") == "WARNING")

        Log.info(f"    {C.GREEN}[+]{C.RESET} {len(findings)} findings "
                 f"({error_count} ERROR, {warning_count} WARNING)")
        if error_count > 0:
            Log.info(f"    {C.DIM}↳ ERROR findings are likely dangerous sinks — verify reachability manually{C.RESET}")
        if timeouts:
            timed_out_rules = sorted({e.get("rule_id", "?").split(".")[-1] for e in timeouts})
            Log.warn(
                f"{len(timeouts)} rule(s) timed out on large files — findings for those rules "
                f"may be incomplete. Rules: {', '.join(timed_out_rules[:5])}"
                + (" …" if len(timed_out_rules) > 5 else "")
            )
            Log.info(f"    {C.DIM}↳ Increase --timeout further or review those files manually{C.RESET}")
        if other_errors:
            def _is_parse_error(e):
                t = e.get("type")
                return (t == "Syntax error"
                        or (isinstance(t, list) and t and t[0] in ("PartialParsing", "Syntax error")))

            syntax_errors = [e for e in other_errors if _is_parse_error(e)]
            config_errors = [e for e in other_errors if not _is_parse_error(e)]
            if syntax_errors:
                # Parse errors on beautified bundles (partial AST, non-JS .js files like
                # Solidity WASM) are expected; log at verbose only.
                Log.verbose(f"{len(syntax_errors)} file(s) had parse errors (partial AST — "
                            f"Semgrep still applied regex rules)")
            for e in config_errors[:3]:
                Log.warn(f"semgrep error: {e.get('type','?')}: {str(e.get('message',''))[:120]}")

        # Store timeout count so the report can display a caveat
        data["_timeout_count"] = len(timeouts)
        semgrep_json.write_text(json.dumps(data), encoding="utf-8")

    except Exception as e:
        Log.warn(f"Could not parse Semgrep output: {e}")

    return semgrep_json


# ---------- Stage 7: Retire.js ----------

def run_retire(target_dir, output_dir):
    stage_header(7, "Retire.js (known-vulnerable libraries)")
    output_file = output_dir / "retire.json"

    cmd = [
        "retire",
        "--path", str(target_dir),
        "--outputformat", "json",
        "--outputpath", str(output_file),
        "--deep",   # content-hash fingerprinting in addition to filename/version matching
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=RETIRE_TIMEOUT)
    except subprocess.TimeoutExpired:
        Log.warn(f"Retire.js timed out after {RETIRE_TIMEOUT}s (large corpus or slow DB fetch)")
        return None

    # Surface any stderr output (DB-fetch errors, SSL issues, etc.)
    if result.stderr and result.stderr.strip():
        stderr_lower = result.stderr.lower()
        if any(kw in stderr_lower for kw in ("error", "fail", "could not", "403", "404", "enotfound")):
            Log.warn(f"retire stderr: {result.stderr.strip()[:300]}")
        else:
            Log.debug(f"retire stderr: {result.stderr.strip()[:300]}")

    # Fallback: some retire versions write to stdout instead of the file
    if not output_file.exists() or output_file.stat().st_size == 0:
        out = (result.stdout or "").strip()
        if out.startswith(("[", "{")):
            output_file.write_text(out)
        else:
            Log.warn("Retire.js produced no parseable output")
            return None

    try:
        data = json.loads(output_file.read_text(encoding="utf-8", errors="replace"))
        # Normalize: new format has {"data": [...]}, legacy may be a bare list
        entries = data.get("data", []) if isinstance(data, dict) else data

        # Detect failed DB fetch — retire returns empty data + errors when offline
        if isinstance(data, dict):
            errors = data.get("errors") or []
            db_errors = [e for e in errors if "jsrepository" in str(e).lower()
                         or "403" in str(e) or "404" in str(e)
                         or "could not" in str(e).lower()]
            if db_errors and not entries:
                Log.warn("Retire.js could not fetch vulnerability database — results unreliable")
                Log.warn(f"  first error: {str(db_errors[0])[:160]}")
                return output_file  # still return — partial info better than none

        vuln_count = 0
        lib_count = 0
        affected_libs = set()
        for entry in entries:
            for r in entry.get("results", []):
                lib_count += 1
                vulns = r.get("vulnerabilities") or []
                if vulns:
                    affected_libs.add(f"{r.get('component')}@{r.get('version')}")
                    vuln_count += len(vulns)

        if lib_count == 0:
            Log.warn(
                "Retire.js detected 0 libraries. If the app uses webpack bundles, "
                "library version strings may be stripped — retire's fingerprints won't match. "
                "Review js-clean/ for bundled library code manually."
            )
        else:
            Log.info(f"    {C.GREEN}[+]{C.RESET} {lib_count} libraries detected, "
                     f"{len(affected_libs)} vulnerable ({vuln_count} CVE findings)")
            if affected_libs:
                Log.info(f"    {C.DIM}↳ Check exploit applicability — not every CVE affects every deployment{C.RESET}")

    except Exception as e:
        Log.warn(f"Could not parse Retire.js output: {e}")

    return output_file


# ---------- Stage 8: TruffleHog ----------

def run_trufflehog(target_dir, output_dir, available_tools, verify):
    stage_header(8, "TruffleHog")
    if not available_tools.get("trufflehog"):
        Log.info("    [-] trufflehog not installed, skipping")
        return None

    th_json = output_dir / "trufflehog.json"
    cmd = ["trufflehog", "filesystem", str(target_dir), "--json"]
    if verify:
        cmd.append("--only-verified")
        Log.warn("--verify-secrets enabled — making real API calls to detected services")
    else:
        cmd.append("--no-verification")
        Log.info(f"    {C.GREEN}[+]{C.RESET} No-verification mode (no network calls)")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=TRUFFLEHOG_TIMEOUT)
    except subprocess.TimeoutExpired:
        Log.warn(f"TruffleHog timed out after {TRUFFLEHOG_TIMEOUT}s")
        return None
    th_json.write_text(result.stdout or "")

    candidates = sum(1 for line in th_json.open() if line.strip())
    Log.info(f"    {C.GREEN}[+]{C.RESET} {candidates} candidates found")
    return th_json


# ---------- Stage 9: HTML report ----------

def parse_jsonl(path):
    if not path or not Path(path).exists():
        return []
    items = []
    try:
        with Path(path).open(encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    items.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        pass
    return items


HTML_CSS = """
:root {
    --bg: #0d1117;
    --surface: #161b22;
    --surface-2: #21262d;
    --border: #30363d;
    --text: #e6edf3;
    --text-dim: #8b949e;
    --accent: #58a6ff;
    --code-bg: #1f2428;
    --error: #ff7b72;
    --error-bg: rgba(255,123,114,.15);
    --warning: #e3b341;
    --warning-bg: rgba(187,128,9,.15);
    --success: #3fb950;
    --success-bg: rgba(63,185,80,.15);
    --hover: #1c2128;
    --nav-h: 52px;
}
*, *::before, *::after { box-sizing: border-box; }
body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    line-height: 1.5;
    margin: 0;
    padding: 0;
    background: var(--bg);
    color: var(--text);
    font-size: 14px;
}
/* ── sticky nav ── */
nav {
    position: sticky;
    top: 0;
    z-index: 100;
    background: var(--surface);
    border-bottom: 1px solid var(--border);
    height: var(--nav-h);
    display: flex;
    align-items: center;
    padding: 0 24px;
    gap: 0;
    overflow-x: auto;
    scrollbar-width: none;
}
nav::-webkit-scrollbar { display: none; }
.nav-brand {
    font-weight: 700;
    color: var(--accent);
    white-space: nowrap;
    margin-right: 24px;
    font-size: 15px;
    letter-spacing: -.3px;
    flex-shrink: 0;
}
.nav-links {
    display: flex;
    gap: 4px;
    align-items: center;
}
.nav-links a {
    color: var(--text-dim);
    text-decoration: none;
    padding: 4px 10px;
    border-radius: 6px;
    font-size: 13px;
    white-space: nowrap;
    transition: color .15s, background .15s;
}
.nav-links a:hover { color: var(--text); background: var(--surface-2); }
.nav-links a.has-findings { color: var(--warning); }
.nav-links a.has-errors   { color: var(--error); }
/* ── layout ── */
.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 28px 24px 60px;
}
header {
    border-bottom: 1px solid var(--border);
    padding-bottom: 20px;
    margin-bottom: 28px;
}
h1 {
    margin: 0 0 12px;
    font-size: 26px;
    font-weight: 700;
    color: var(--text);
}
h3 {
    font-size: 14px;
    font-weight: 600;
    margin: 20px 0 10px;
    color: var(--text-dim);
}
.meta {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 6px 16px;
    color: var(--text-dim);
    font-size: 13px;
}
.meta dt { font-weight: 600; color: var(--text); }
.meta dd { margin: 0; }
/* ── collapsible sections ── */
details.section {
    border: 1px solid var(--border);
    border-radius: 8px;
    margin-bottom: 16px;
    background: var(--surface);
    overflow: hidden;
}
details.section > summary {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 14px 18px;
    cursor: pointer;
    user-select: none;
    list-style: none;
    font-size: 16px;
    font-weight: 600;
    color: var(--text);
    border-bottom: 1px solid transparent;
    transition: background .12s;
}
details.section[open] > summary {
    border-bottom-color: var(--border);
    background: var(--surface-2);
}
details.section > summary:hover { background: var(--surface-2); }
details.section > summary::before {
    content: "▶";
    font-size: 11px;
    color: var(--text-dim);
    transition: transform .15s;
    flex-shrink: 0;
}
details.section[open] > summary::before { transform: rotate(90deg); }
.section-body { padding: 16px 18px; }
/* inner collapsible (sub-sections) */
details.sub {
    border: 1px solid var(--border);
    border-radius: 6px;
    margin-bottom: 10px;
    background: var(--bg);
}
details.sub > summary {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 9px 14px;
    cursor: pointer;
    user-select: none;
    list-style: none;
    font-size: 13px;
    font-weight: 600;
    color: var(--text-dim);
    transition: color .12s;
}
details.sub > summary:hover { color: var(--text); }
details.sub > summary::before {
    content: "▶";
    font-size: 10px;
    color: var(--text-dim);
    transition: transform .15s;
}
details.sub[open] > summary::before { transform: rotate(90deg); }
.sub-body { padding: 0 14px 12px; }
/* ── code / mono ── */
code, .mono {
    font-family: "SF Mono", Monaco, Consolas, "Courier New", monospace;
    font-size: 12px;
    background: var(--code-bg);
    padding: 1px 6px;
    border-radius: 4px;
    word-break: break-all;
    color: var(--text);
}
/* ── summary stat grid ── */
.summary-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
    gap: 10px;
    margin: 4px 0 8px;
}
.stat {
    background: var(--surface-2);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 12px 14px;
}
.stat-label {
    color: var(--text-dim);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: .5px;
    margin-bottom: 5px;
}
.stat-value {
    font-size: 22px;
    font-weight: 700;
}
.stat-value.error   { color: var(--error); }
.stat-value.warning { color: var(--warning); }
.stat-value.success { color: var(--success); }
/* ── tables ── */
table {
    width: 100%;
    border-collapse: collapse;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    overflow: hidden;
    margin: 6px 0 12px;
    font-size: 13px;
}
th, td {
    text-align: left;
    padding: 7px 11px;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
}
th {
    background: var(--surface-2);
    font-weight: 600;
    color: var(--text-dim);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: .4px;
}
tr:last-child td { border-bottom: none; }
tr:hover { background: var(--hover); }
/* ── copy button ── */
.file-cell { display: flex; align-items: center; gap: 6px; min-width: 0; }
.file-cell code { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1; min-width: 0; }
.copy-btn {
    flex-shrink: 0;
    background: none;
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--text-dim);
    cursor: pointer;
    font-size: 11px;
    line-height: 1;
    padding: 2px 5px;
    transition: color .15s, border-color .15s, background .15s;
    white-space: nowrap;
}
.copy-btn:hover { color: var(--accent); border-color: var(--accent); background: var(--surface-2); }
.copy-btn.copied { color: var(--success); border-color: var(--success); }
/* ── badges ── */
.badge {
    display: inline-block;
    padding: 1px 8px;
    border-radius: 10px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: .3px;
    vertical-align: middle;
}
.badge.error   { background: var(--error-bg);   color: var(--error); }
.badge.warning { background: var(--warning-bg); color: var(--warning); }
.badge.success { background: var(--success-bg); color: var(--success); }
.badge.method  {
    background: var(--code-bg);
    color: var(--text);
    font-family: "SF Mono", Monaco, Consolas, monospace;
    font-size: 11px;
}
.badge.neutral { background: var(--surface-2); color: var(--text-dim); }
/* ── misc ── */
.empty {
    color: var(--text-dim);
    font-style: italic;
    padding: 8px 0;
    font-size: 13px;
}
.notice {
    padding: 10px 14px;
    border-radius: 6px;
    font-size: 13px;
    margin-bottom: 10px;
    border-left: 3px solid;
}
.notice.warn { background: var(--warning-bg); border-color: var(--warning); color: var(--warning); }
.notice.err  { background: var(--error-bg);   border-color: var(--error);   color: var(--error); }
.next-steps {
    background: var(--surface-2);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 14px 18px;
}
.next-steps ol { margin: 0; padding-left: 20px; }
.next-steps li { margin: 5px 0; color: var(--text-dim); font-size: 13px; }
footer {
    margin-top: 48px;
    padding-top: 14px;
    border-top: 1px solid var(--border);
    color: var(--text-dim);
    font-size: 12px;
    text-align: center;
}
@media print {
    body { background: white; --bg: white; --surface: white; --text: black; }
    nav { display: none; }
    details.section, details.sub { border: none; }
    details.section > summary { display: none; }
}
"""


def html_escape(s):
    import html
    return html.escape(str(s)) if s is not None else ""


def generate_report(target, output_dir, results):
    stage_header(9, "Generating HTML report")
    report_path = output_dir / "report.html"
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Absolute path to js-clean/ — used to build full file paths in copy buttons
    js_clean_abs = str((output_dir / "js-clean").resolve())

    # filename → original source URL (populated by download_js / discover_nested_js)
    _url_map_path = output_dir / "url-map.json"
    url_map: dict[str, str] = (
        json.loads(_url_map_path.read_text()) if _url_map_path.exists() else {}
    )

    def copy_btn(full_path, label="⧉"):
        """Render a copy-to-clipboard button for a file path."""
        safe = full_path.replace("'", "&#39;").replace('"', "&quot;")
        return f"<button class='copy-btn' data-copy='{safe}' title='{safe}'>{label}</button>"

    def file_cell(filename, base_dir=None):
        """Render a <td> with filename + copy-path button; add URL copy button when known."""
        if not filename or filename == "?":
            return "<td>—</td>"
        base = base_dir or js_clean_abs
        full = f"{base}/{filename}" if not filename.startswith("/") else filename
        fname_only = Path(filename).name
        src_url = url_map.get(fname_only, "")
        url_btn = (f"<button class='copy-btn' data-copy='{html_escape(src_url)}' "
                   f"title='Copy source URL: {html_escape(src_url)}'>🔗</button>"
                   if src_url else "")
        return (f"<td><div class='file-cell'>"
                f"<code title='{html_escape(full)}'>{html_escape(filename)}</code>"
                f"{copy_btn(full)}{url_btn}"
                f"</div></td>")

    # ── helpers ─────────────────────────────────────────────────────
    def section(id_, title, badge_text="", badge_cls="neutral", open_=True):
        badge = (f" <span class='badge {badge_cls}'>{html_escape(str(badge_text))}</span>"
                 if badge_text != "" else "")
        open_attr = " open" if open_ else ""
        return (f"<details class='section' id='{id_}'{open_attr}>\n"
                f"<summary>{html_escape(title)}{badge}</summary>\n"
                f"<div class='section-body'>")

    def end_section():
        return "</div></details>"

    def sub(title, badge_text="", badge_cls="neutral", open_=True):
        badge = (f" <span class='badge {badge_cls}'>{html_escape(str(badge_text))}</span>"
                 if badge_text != "" else "")
        open_attr = " open" if open_ else ""
        return (f"<details class='sub'{open_attr}>\n"
                f"<summary>{html_escape(title)}{badge}</summary>\n"
                f"<div class='sub-body'>")

    def end_sub():
        return "</div></details>"

    # ── compute nav highlight classes ────────────────────────────────
    def nav_cls(key, threshold=1):
        return "has-errors" if results.get(key, 0) >= threshold else ""

    parts = []
    parts.append("<!DOCTYPE html>")
    parts.append("<html lang='en'>")
    parts.append("<head>")
    parts.append("<meta charset='utf-8'>")
    parts.append("<meta name='viewport' content='width=device-width,initial-scale=1'>")
    parts.append(f"<title>JS Analysis — {html_escape(target)}</title>")
    parts.append(f"<style>{HTML_CSS}</style>")
    parts.append("</head>")
    parts.append("<body>")

    # ── sticky nav ───────────────────────────────────────────────────
    semgrep_cls = "has-errors" if results.get("semgrep_error", 0) else (
                  "has-findings" if results.get("semgrep_total", 0) else "")
    retire_cls  = "has-errors" if results.get("retire_vuln_libs", 0) else ""
    secrets_cls = "has-findings" if (results.get("jsluice_secrets", 0) or
                                     results.get("th_candidates", 0) or
                                     results.get("secrets_ext_count", 0)) else ""

    parts.append("<nav>")
    parts.append("<span class='nav-brand'>🔍 jspect</span>")
    parts.append("<div class='nav-links'>")
    for href, label, cls in [
        ("#summary",     "Summary",       ""),
        ("#endpoints",   "Endpoints",     "has-findings" if results.get("endpoint_count",0) else ""),
        ("#live",        "Live",          "has-findings" if results.get("live_count",0) else ""),
        ("#http-calls",  "HTTP Calls",    "has-findings" if results.get("http_calls_count",0) else ""),
        ("#semgrep",     "Semgrep",       semgrep_cls),
        ("#secrets",     "Secrets",       secrets_cls),
        ("#retire",      "Libraries",     retire_cls),
        ("#comments",    "Comments",      ""),
        ("#next-steps",  "Next Steps",    ""),
    ]:
        parts.append(f"<a href='{href}' class='{cls}'>{html_escape(label)}</a>")
    parts.append("</div></nav>")

    # ── page header ──────────────────────────────────────────────────
    parts.append("<div class='container'>")
    parts.append("<header>")
    parts.append("<h1>JavaScript Analysis Report</h1>")
    parts.append("<dl class='meta'>")
    parts.append(f"<dt>Target</dt><dd><code>{html_escape(target)}</code></dd>")
    parts.append(f"<dt>Run</dt><dd>{html_escape(now)}</dd>")
    parts.append(f"<dt>Output</dt><dd><code>{html_escape(str(output_dir))}</code></dd>")
    parts.append("</dl>")
    parts.append("</header>")

    # ── Summary ──────────────────────────────────────────────────────
    parts.append(section("summary", "Summary", open_=True))
    parts.append("<div class='summary-grid'>")
    stats = [
        ("URLs crawled",          results.get("url_count", 0),              ""),
        ("JS files",              results.get("js_count", 0),               ""),
        ("Endpoints found",       results.get("endpoint_count", 0),         ""),
        ("Live endpoints",        results.get("live_count", 0),             ""),
        ("HTTP calls (JS)",       results.get("http_calls_count", 0),       ""),
        ("Dangling JS",           results.get("dangling_count", 0),
         "warning" if results.get("dangling_count", 0) else ""),
        ("Exposed maps",          results.get("exposed_maps_count", 0),
         "warning" if results.get("exposed_maps_count", 0) else ""),
        ("Wayback maps",          results.get("wayback_maps_count", 0),
         "error" if results.get("wayback_only_count", 0)
         else ("warning" if results.get("wayback_maps_count", 0) else "")),
        ("Recon downloads",       results.get("recon_downloaded", 0),
         "success" if results.get("recon_downloaded", 0) else ""),
        ("Recon secrets",         results.get("recon_secrets_found", 0),
         "error" if results.get("recon_secrets_found", 0) else ""),
        ("Well-known hits",       results.get("well_known_hits", 0),
         "success" if results.get("well_known_hits", 0) else ""),
        ("Well-known leaks",      results.get("well_known_leaks", 0),
         "error" if results.get("well_known_leaks", 0) else ""),
        ("URLs harvested",        results.get("well_known_harvested", 0),
         "success" if results.get("well_known_harvested", 0) else ""),
        ("JSON exposures",        results.get("json_exposures_count", 0),
         "warning" if results.get("json_exposures_count", 0) else ""),
        ("Swagger endpoints",     results.get("swagger_endpoints_count", 0),
         "success" if results.get("swagger_endpoints_count", 0) else ""),
        ("Dev comments",          results.get("comments_count", 0),         ""),
        ("Vulnerable libs",       results.get("retire_vuln_libs", 0),
         "error" if results.get("retire_vuln_libs", 0) else ""),
        ("JSluice secrets",       results.get("jsluice_secrets", 0),
         "warning" if results.get("jsluice_secrets", 0) else ""),
        ("Ext. secrets",          results.get("secrets_ext_count", 0),
         "warning" if results.get("secrets_ext_count", 0) else ""),
        ("TruffleHog hits",       results.get("th_candidates", 0),
         "warning" if results.get("th_candidates", 0) else ""),
        ("Semgrep ERROR",         results.get("semgrep_error", 0),
         "error" if results.get("semgrep_error", 0) else ""),
        ("Semgrep total",         results.get("semgrep_total", 0),
         "warning" if results.get("semgrep_total", 0) else ""),
        ("Semgrep timeouts",      results.get("semgrep_timeouts", 0),
         "warning" if results.get("semgrep_timeouts", 0) else ""),
        ("Source maps",           "yes" if results.get("source_maps") else "no",
         "success" if results.get("source_maps") else ""),
    ]
    for label, value, cls in stats:
        parts.append(f"<div class='stat'><div class='stat-label'>{html_escape(label)}</div>"
                     f"<div class='stat-value {cls}'>{html_escape(value)}</div></div>")
    parts.append("</div>")
    parts.append(end_section())

    # ── Endpoints ────────────────────────────────────────────────────
    endpoints = parse_jsonl(results.get("endpoints_file"))
    target_host = urlparse(target).hostname or ""
    if endpoints:
        endpoints = [e for e in endpoints if e.get("url")]

    # Build a set of URLs that live-validated as 4xx/5xx — these can't be open
    # redirects regardless of how suspicious their params look. We index by both
    # the absolute URL and the path-only form so URL-extracted vs. resolved
    # candidates both line up.
    target_base_for_match = f"{urlparse(target).scheme}://{urlparse(target).netloc}" if target else ""
    dead_urls: set[str] = set()
    live_rows_for_filter = parse_jsonl(results.get("live_endpoints_file"))
    for r in live_rows_for_filter:
        st = r.get("status")
        if isinstance(st, int) and st >= 400:
            u = (r.get("url") or "").strip()
            if u:
                dead_urls.add(u)
                # also index the path-only form for cross-matching
                try:
                    p = urlparse(u)
                    if p.path:
                        path_form = p.path + (("?" + p.query) if p.query else "")
                        dead_urls.add(path_form)
                except Exception:
                    pass

    def _is_dead(endpoint):
        u = (endpoint.get("url") or "").strip()
        if not u:
            return False
        if u in dead_urls:
            return True
        # Try resolving relative paths against the target host
        if target_base_for_match and u.startswith("/"):
            if (target_base_for_match + u) in dead_urls:
                return True
        return False

    in_scope   = [e for e in endpoints if is_in_scope(e.get("url"), target_host)] if endpoints else []
    out_scope  = [e for e in endpoints if not is_in_scope(e.get("url"), target_host)] if endpoints else []
    api_eps    = [e for e in in_scope if looks_like_api(e.get("url"))]
    # Open-redirect candidates: drop any whose live-probe returned 4xx/5xx.
    # An endpoint that doesn't exist on the server can't be an open redirect.
    _all_redir  = [e for e in endpoints if is_open_redirect_candidate(e)] if endpoints else []
    redir_eps   = [e for e in _all_redir if not _is_dead(e)]
    redir_dropped = len(_all_redir) - len(redir_eps)
    body_eps   = [e for e in in_scope if e.get("bodyParams")]
    query_eps  = [e for e in in_scope if e.get("queryParams") and not is_open_redirect_candidate(e)]

    ep_badge_cls = "warning" if redir_eps else ("" if not in_scope else "")
    parts.append(section("endpoints", "Endpoints",
                         f"{len(in_scope)} in scope · {len(out_scope)} external",
                         ep_badge_cls, open_=bool(endpoints)))

    if not endpoints:
        parts.append("<p class='empty'>No endpoints extracted.</p>")
    else:
        parts.append(f"<p class='empty'>Target host: <code>{html_escape(target_host)}</code> · "
                     f"{len(in_scope)} in scope · {len(out_scope)} external references</p>")

        # Open redirect candidates
        if redir_eps:
            badge_text = str(len(redir_eps))
            if redir_dropped:
                badge_text += f" (live-probe filtered {redir_dropped} 4xx/5xx)"
            parts.append(sub("Open redirect candidates", badge_text, "warning", open_=True))
            parts.append("<table><thead><tr><th>Method</th><th>URL</th><th>Param</th><th>Source</th></tr></thead><tbody>")
            seen = set()
            for e in redir_eps:
                key = (e.get("method"), e.get("url"))
                if key in seen: continue
                seen.add(key)
                method = html_escape(e.get("method") or "GET")
                url    = html_escape(e.get("url", ""))
                params = [p for p in (e.get("queryParams") or []) if p.lower() in REDIRECT_PARAMS]
                if not params:
                    ul = (e.get("url") or "").lower()
                    for p in REDIRECT_PARAMS:
                        if f"?{p}=" in ul or f"&{p}=" in ul:
                            params.append(p); break
                params_str = html_escape(", ".join(params))
                source = html_escape(Path(e.get("filename","")).name) if e.get("filename") else ""
                parts.append(f"<tr><td><span class='badge method'>{method}</span></td>"
                             f"<td><code>{url}</code></td><td><code>{params_str}</code></td>"
                             f"<td><code>{source}</code></td></tr>")
            parts.append("</tbody></table>")
            parts.append(end_sub())

        # API routes
        parts.append(sub("API-like routes (in scope)", len(api_eps), "neutral", open_=bool(api_eps)))
        if api_eps:
            parts.append("<table><thead><tr><th>Method</th><th>URL</th><th>Source</th></tr></thead><tbody>")
            seen = set()
            for e in api_eps:
                key = (e.get("method"), e.get("url"))
                if key in seen: continue
                seen.add(key)
                parts.append(f"<tr><td><span class='badge method'>{html_escape(e.get('method') or 'GET')}</span></td>"
                             f"<td><code>{html_escape(e.get('url',''))}</code></td>"
                             f"<td><code>{html_escape(Path(e.get('filename','')).name) if e.get('filename') else ''}</code></td></tr>")
            parts.append("</tbody></table>")
        else:
            parts.append("<p class='empty'>No API routes found.</p>")
        parts.append(end_sub())

        # Body-param endpoints
        if body_eps:
            parts.append(sub("Endpoints with body params", len(body_eps), "neutral", open_=False))
            parts.append("<table><thead><tr><th>Method</th><th>URL</th><th>Body params</th></tr></thead><tbody>")
            seen = set()
            for e in body_eps:
                key = (e.get("method"), e.get("url"))
                if key in seen: continue
                seen.add(key)
                parts.append(f"<tr><td><span class='badge method'>{html_escape(e.get('method') or 'POST')}</span></td>"
                             f"<td><code>{html_escape(e.get('url',''))}</code></td>"
                             f"<td><code>{html_escape(', '.join(e.get('bodyParams',[])))}</code></td></tr>")
            parts.append("</tbody></table>")
            parts.append(end_sub())

        # Query-param endpoints
        if query_eps:
            parts.append(sub("Endpoints with query params", len(query_eps), "neutral", open_=False))
            parts.append("<table><thead><tr><th>Method</th><th>URL</th><th>Query params</th></tr></thead><tbody>")
            seen = set(); shown = 0
            for e in query_eps:
                key = (e.get("method"), e.get("url"))
                if key in seen: continue
                seen.add(key)
                parts.append(f"<tr><td><span class='badge method'>{html_escape(e.get('method') or 'GET')}</span></td>"
                             f"<td><code>{html_escape(e.get('url',''))}</code></td>"
                             f"<td><code>{html_escape(', '.join(e.get('queryParams',[])))}</code></td></tr>")
                shown += 1
                if shown >= 100:
                    parts.append(f"<tr><td colspan='3' class='empty'>{len(query_eps)-shown} more — see endpoints.json</td></tr>"); break
            parts.append("</tbody></table>")
            parts.append(end_sub())

        # External hosts
        if out_scope:
            ext_hosts = {}
            for e in out_scope:
                url = (e.get("url") or "").strip()
                if not url: continue
                try:
                    h = urlparse(url).hostname if url.startswith(("http://","https://")) else urlparse("https:"+url).hostname
                except Exception: h = None
                if h: ext_hosts.setdefault(h, []).append(url)
            parts.append(sub(f"External references ({len(ext_hosts)} hosts)", len(out_scope), "neutral", open_=False))
            parts.append("<p class='empty'>Third-party URLs — review for supply-chain risk.</p>")
            parts.append("<table><thead><tr><th>Host</th><th>Refs</th><th>Example</th></tr></thead><tbody>")
            for host, urls in sorted(ext_hosts.items(), key=lambda kv: -len(kv[1])):
                parts.append(f"<tr><td><code>{html_escape(host)}</code></td>"
                             f"<td>{len(urls)}</td>"
                             f"<td><code>{html_escape(urls[0][:120])}</code></td></tr>")
            parts.append("</tbody></table>")
            parts.append(end_sub())

    parts.append(end_section())

    # ── Live endpoints ───────────────────────────────────────────────
    live_eps = parse_jsonl(results.get("live_endpoints_file"))
    live_groups = {
        "Auth-protected (401/403)":  ([], "error"),
        "Successful (2xx)":          ([], "success"),
        "Server error (5xx)":        ([], "error"),
        "Redirects (3xx)":           ([], "neutral"),
        "Other 4xx":                 ([], "warning"),
        "Connection error":          ([], "warning"),
    }
    for e in live_eps:
        s = e.get("status")
        if s is None:             live_groups["Connection error"][0].append(e)
        elif s in (401, 403):     live_groups["Auth-protected (401/403)"][0].append(e)
        elif 200 <= s < 300:      live_groups["Successful (2xx)"][0].append(e)
        elif 300 <= s < 400:      live_groups["Redirects (3xx)"][0].append(e)
        elif 400 <= s < 500:      live_groups["Other 4xx"][0].append(e)
        elif 500 <= s < 600:      live_groups["Server error (5xx)"][0].append(e)

    auth_count  = len(live_groups["Auth-protected (401/403)"][0])
    live_badge  = "error" if auth_count else ("" if not live_eps else "neutral")

    # Detect & surface truncation — the operator MUST know when 91% of the
    # endpoints silently never got probed.
    live_meta_path = Path(results.get("live_endpoints_file") or "").parent / "live-endpoints-meta.json"
    live_meta = {}
    if live_meta_path.exists():
        try: live_meta = json.loads(live_meta_path.read_text())
        except Exception: pass
    title = "Live Endpoints"
    if live_meta.get("truncated"):
        title += f" ({live_meta.get('validated', 0)} of {live_meta.get('total_in_scope', '?')} probed)"

    parts.append(section("live", title, len(live_eps), live_badge, open_=bool(live_eps)))
    if live_meta.get("truncated"):
        parts.append(
            f"<div class='notice warn'>⚠ Only the top {live_meta.get('validated', 0)} "
            f"of {live_meta.get('total_in_scope', '?')} in-scope endpoints were probed "
            f"(API/short-path priority). Pass <code>--max-endpoints 0</code> for unlimited.</div>"
        )
    if not live_eps:
        parts.append("<p class='empty'>No endpoints probed.</p>")
    else:
        parts.append("<p class='empty'>Auth-protected and 5xx responses deserve manual review first.</p>")
        for label, (items, bcls) in live_groups.items():
            if not items: continue
            open_sub = label in ("Auth-protected (401/403)", "Server error (5xx)")
            parts.append(sub(label, len(items), bcls, open_=open_sub))
            parts.append("<table><thead><tr><th>Status</th><th>URL</th><th>Type</th><th>Size</th><th>Title</th></tr></thead><tbody>")
            for e in items[:100]:
                s = e.get("status")
                s_str = str(s) if s is not None else html_escape(e.get("error","ERR"))
                size  = e.get("size"); size_str = f"{size:,}" if isinstance(size,int) else ""
                parts.append(f"<tr><td><code>{s_str}</code></td>"
                             f"<td><code>{html_escape(e.get('url',''))}</code></td>"
                             f"<td><code>{html_escape(e.get('content_type') or '')}</code></td>"
                             f"<td>{size_str}</td>"
                             f"<td>{html_escape(e.get('title') or '')}</td></tr>")
            if len(items) > 100:
                parts.append(f"<tr><td colspan='5' class='empty'>{len(items)-100} more — see live-endpoints.json</td></tr>")
            parts.append("</tbody></table>")
            parts.append(end_sub())
    parts.append(end_section())

    # ── HTTP Calls ───────────────────────────────────────────────────
    http_calls = parse_jsonl(results.get("http_calls_file"))
    parts.append(section("http-calls", "HTTP Calls (extracted from JS)",
                         len(http_calls) if http_calls else 0,
                         "warning" if http_calls else "neutral",
                         open_=bool(http_calls)))
    if not http_calls:
        parts.append("<p class='empty'>No HTTP call patterns detected.</p>")
    else:
        parts.append("<p class='empty'>URLs the JavaScript actively calls at runtime — "
                     "extracted from fetch / axios / XHR / Angular HttpClient. "
                     "Cross-reference with the endpoint list above for gaps.</p>")
        by_kind = {}
        for c in http_calls:
            by_kind.setdefault(c.get("kind","?"), []).append(c)

        for kind, items in sorted(by_kind.items(), key=lambda kv: -len(kv[1])):
            parts.append(sub(f"{kind} ({len(items)})", len(items), "neutral", open_=len(items) <= 30))
            parts.append("<table><thead><tr><th>Method</th><th>URL</th><th>File</th><th>Line</th></tr></thead><tbody>")
            seen = set()
            for c in items[:200]:
                key = (c.get("method"), c.get("url"))
                if key in seen: continue
                seen.add(key)
                parts.append(f"<tr><td><span class='badge method'>{html_escape(c.get('method','?'))}</span></td>"
                             f"<td><code>{html_escape(c.get('url',''))}</code></td>"
                             + file_cell(c.get('file',''))
                             + f"<td>{html_escape(str(c.get('line','')))}</td></tr>")
            if len(items) > 200:
                parts.append(f"<tr><td colspan='4' class='empty'>{len(items)-200} more — see http-calls.json</td></tr>")
            parts.append("</tbody></table>")
            parts.append(end_sub())
    parts.append(end_section())

    # ── Secrets ──────────────────────────────────────────────────────
    jsluice_secs  = parse_jsonl(results.get("secrets_file"))
    th_cands      = parse_jsonl(results.get("trufflehog_file"))
    ext_secs      = parse_jsonl(results.get("secrets_ext_file"))
    total_secs    = len(jsluice_secs) + len(th_cands) + len(ext_secs)
    parts.append(section("secrets", "Secret Candidates",
                         total_secs, "warning" if total_secs else "neutral",
                         open_=bool(total_secs)))
    if not total_secs:
        parts.append("<p class='empty'>No secret candidates found across JSluice, TruffleHog, or extended patterns.</p>")
    else:
        parts.append("<p class='empty'>Values are partially redacted. Inspect the raw JS files "
                     "before any validation — check ROE before making live API calls.</p>")

        if ext_secs:
            by_kind = {}
            for s in ext_secs:
                by_kind.setdefault(s.get("kind","?"), []).append(s)
            parts.append(sub(f"Extended pattern matches ({len(ext_secs)})", len(ext_secs), "warning", open_=True))
            parts.append("<table><thead><tr><th>Kind</th><th>Value (redacted)</th><th>File</th><th>Line</th></tr></thead><tbody>")
            for s in ext_secs[:100]:
                kind_cls = "error" if s.get("kind","") in ("jwt","aws-key-id","private-key","stripe-key") else "warning"
                parts.append(f"<tr><td><span class='badge {kind_cls}'>{html_escape(s.get('kind','?'))}</span></td>"
                             f"<td><code>{html_escape(s.get('match','?'))}</code></td>"
                             + file_cell(s.get('file',''))
                             + f"<td>{html_escape(str(s.get('line','')))}</td></tr>")
            if len(ext_secs) > 100:
                parts.append(f"<tr><td colspan='4' class='empty'>{len(ext_secs)-100} more — see secrets-extended.json</td></tr>")
            parts.append("</tbody></table>")
            parts.append(end_sub())

        if jsluice_secs:
            parts.append(sub(f"JSluice ({len(jsluice_secs)})", len(jsluice_secs), "warning", open_=True))
            parts.append("<table><thead><tr><th>Kind</th><th>Source file</th><th>Match</th></tr></thead><tbody>")
            for s in jsluice_secs:
                kind = html_escape(s.get("kind","?"))
                filename = html_escape(Path(s.get("filename","?")).name)
                data = s.get("data",{})
                match = data.get("key") or data.get("match") or data.get("value") or "(see raw)"
                match = str(match)
                if len(match) > 80: match = match[:80]+"..."
                parts.append(f"<tr><td><span class='badge warning'>{kind}</span></td>"
                             f"<td><code>{filename}</code></td>"
                             f"<td><code>{html_escape(match)}</code></td></tr>")
            parts.append("</tbody></table>")
            parts.append(end_sub())

        if th_cands:
            verified_label = "Verified" if results.get("th_verified") else "Unverified (no API calls)"
            parts.append(sub(f"TruffleHog — {verified_label} ({len(th_cands)})", len(th_cands), "warning", open_=True))
            parts.append("<table><thead><tr><th>Detector</th><th>File</th><th>Status</th></tr></thead><tbody>")
            for s in th_cands:
                detector = html_escape(s.get("DetectorName","?"))
                fp = (s.get("SourceMetadata",{}).get("Data",{}).get("Filesystem",{}).get("file","?"))
                # TruffleHog already stores the full path; show name, copy full path
                file_name = Path(fp).name if fp != "?" else "?"
                status = ("<span class='badge error'>Verified</span>" if s.get("Verified")
                          else "<span class='badge warning'>Unverified</span>")
                parts.append(f"<tr><td><code>{detector}</code></td>"
                             + file_cell(file_name, base_dir=str(Path(fp).parent) if fp != "?" else None)
                             + f"<td>{status}</td></tr>")
            parts.append("</tbody></table>")
            parts.append(end_sub())

    parts.append(end_section())

    # ── Semgrep ──────────────────────────────────────────────────────
    semgrep_file = results.get("semgrep_file")
    sem_findings = []; timeout_count = 0; timed_out_rules = []
    if semgrep_file:
        try:
            sem_data     = json.loads(Path(semgrep_file).read_text(encoding="utf-8", errors="replace"))
            sem_findings = sem_data.get("results", [])
            timeout_count = sem_data.get("_timeout_count", 0)
            timed_out_rules = sorted({e.get("rule_id","?").split(".")[-1]
                                      for e in sem_data.get("errors",[])
                                      if e.get("type") == "Timeout"})
        except Exception:
            pass

    sem_badge = "error" if results.get("semgrep_error",0) else ("warning" if sem_findings else "neutral")
    parts.append(section("semgrep", "Semgrep — SAST / DOM Sinks",
                         len(sem_findings), sem_badge, open_=bool(sem_findings)))
    if timeout_count:
        rule_list = ", ".join(timed_out_rules[:8]) + ("…" if len(timed_out_rules) > 8 else "")
        parts.append(f"<div class='notice warn'>⚠ {timeout_count} rule(s) timed out — "
                     f"results may be incomplete. Rules: <code>{html_escape(rule_list)}</code></div>")
    if not sem_findings:
        parts.append("<p class='empty'>No findings.</p>")
    else:
        sem_errors   = [f for f in sem_findings if f.get("extra",{}).get("severity") == "ERROR"]
        sem_warnings = [f for f in sem_findings if f.get("extra",{}).get("severity") == "WARNING"]
        for level, items, bcls in [("ERROR", sem_errors, "error"), ("WARNING", sem_warnings, "warning")]:
            if not items: continue
            parts.append(sub(f"{level} ({len(items)})", len(items), bcls, open_=True))
            parts.append("<table><thead><tr><th>Rule</th><th>File</th><th>Line</th><th>Message</th></tr></thead><tbody>")
            for f in items[:50]:
                rule     = html_escape(f.get("check_id","?").split(".")[-1])
                full_path = f.get("path","?")   # semgrep stores the full analysed path
                fname    = Path(full_path).name
                line     = html_escape(str(f.get("start",{}).get("line","?")))
                msg      = f.get("extra",{}).get("message","")[:200].replace("\n"," ")
                parts.append(f"<tr><td><code>{rule}</code></td>"
                             + file_cell(fname, base_dir=str(Path(full_path).parent))
                             + f"<td>{line}</td>"
                             f"<td>{html_escape(msg)}</td></tr>")
            if len(items) > 50:
                parts.append(f"<tr><td colspan='4' class='empty'>{len(items)-50} more — see semgrep.json</td></tr>")
            parts.append("</tbody></table>")
            parts.append(end_sub())
    parts.append(end_section())

    # ── Retire.js ────────────────────────────────────────────────────
    retire_file = results.get("retire_file")
    retire_libs = {}
    if retire_file:
        try:
            data    = json.loads(Path(retire_file).read_text(encoding="utf-8", errors="replace"))
            entries = data.get("data",[]) if isinstance(data,dict) else data
            for entry in entries:
                fname = Path(entry.get("file","?")).name
                for r in entry.get("results",[]):
                    key = f"{r.get('component','?')}_at_{r.get('version','?')}"
                    if key not in retire_libs:
                        retire_libs[key] = {"component":r.get("component","?"),
                                            "version":r.get("version","?"),
                                            "files":set(), "vulns":[]}
                    retire_libs[key]["files"].add(fname)
                    for v in (r.get("vulnerabilities") or []):
                        retire_libs[key]["vulns"].append(v)
        except Exception as e:
            Log.debug(f"could not parse Retire.js output for report: {e}")

    vuln_libs = {k:v for k,v in retire_libs.items() if v["vulns"]}
    ret_badge = "error" if vuln_libs else "neutral"
    parts.append(section("retire", "Libraries — Retire.js",
                         f"{len(retire_libs)} detected, {len(vuln_libs)} vulnerable",
                         ret_badge, open_=bool(vuln_libs)))
    if not retire_libs:
        parts.append("<div class='notice warn'>⚠ 0 libraries detected. Webpack-bundled apps strip the "
                     "version strings Retire.js fingerprints against — review js-clean/ manually "
                     "for inline library code.</div>")
    elif vuln_libs:
        sev_rank = {"critical":0,"high":1,"medium":2,"low":3}
        def highest_sev(lib):
            return min((sev_rank.get((v.get("severity") or "low").lower(),4)
                        for v in lib["vulns"]), default=4)
        parts.append("<table><thead><tr><th>Library</th><th>Version</th><th>Severity</th>"
                     "<th>CVEs</th><th>Found in</th></tr></thead><tbody>")
        for key, lib in sorted(vuln_libs.items(), key=lambda kv:(highest_sev(kv[1]),kv[0])):
            sevs = sorted({(v.get("severity") or "low").lower() for v in lib["vulns"]},
                          key=lambda s: sev_rank.get(s,4))
            sev_badges = " ".join(
                f"<span class='badge {'error' if s in ('critical','high') else 'warning'}'>"
                f"{html_escape(s)}</span>" for s in sevs)
            cves = set()
            for v in lib["vulns"]:
                for c in ((v.get("identifiers") or {}).get("CVE") or []): cves.add(c)
            cves_str = html_escape(", ".join(sorted(cves))) if cves else f"{len(lib['vulns'])} advisories"
            parts.append(f"<tr><td><code>{html_escape(lib['component'])}</code></td>"
                        f"<td><code>{html_escape(lib['version'])}</code></td>"
                        f"<td>{sev_badges}</td><td><code>{cves_str}</code></td>"
                        f"<td><code>{html_escape(', '.join(sorted(lib['files']))[:120])}</code></td></tr>")
        parts.append("</tbody></table>")
    else:
        parts.append(f"<p class='empty'>{len(retire_libs)} libraries detected — none with known vulnerabilities.</p>")
    parts.append(end_section())

    # ── Developer comments ───────────────────────────────────────────
    comments = parse_jsonl(results.get("comments_file"))
    parts.append(section("comments", "Developer Comments",
                         len(comments), "warning" if comments else "neutral",
                         open_=bool(comments)))
    if not comments:
        parts.append("<p class='empty'>No interesting developer comments found.</p>")
    else:
        parts.append("<p class='empty'>Comments extracted from JS. Often surface unfinished work, "
                     "internal references, or hints at hidden functionality.</p>")
        by_kind = {}
        for c in comments:
            by_kind.setdefault(c.get("kind","?"), []).append(c)
        order = ["credential_mention","leftover","lint_disabled","cve_reference","internal_url",
                 "env_reference","fixme","hack","xxx","todo","ticket_reference","authorship"]
        for kind in order + [k for k in by_kind if k not in order]:
            items = by_kind.get(kind)
            if not items: continue
            bcls = "error" if kind in ("credential_mention","leftover","cve_reference") else (
                   "warning" if kind in ("lint_disabled","internal_url") else "neutral")
            parts.append(sub(f"{kind.replace('_',' ')} ({len(items)})", len(items), bcls,
                             open_=kind in ("credential_mention","leftover","cve_reference")))
            parts.append("<table><thead><tr><th>File</th><th>Line</th><th>Comment</th></tr></thead><tbody>")
            for c in items[:30]:
                parts.append("<tr>"
                             + file_cell(c.get('file',''))
                             + f"<td>{html_escape(str(c.get('line','?')))}</td>"
                             f"<td><code>{html_escape(c.get('text',''))}</code></td></tr>")
            if len(items) > 30:
                parts.append(f"<tr><td colspan='3' class='empty'>{len(items)-30} more — see comments.json</td></tr>")
            parts.append("</tbody></table>")
            parts.append(end_sub())
    parts.append(end_section())

    # ── Dangling JS ──────────────────────────────────────────────────
    dangling = parse_jsonl(results.get("dangling_file"))
    if dangling:
        parts.append(section("dangling", "Dangling JS References",
                             len(dangling), "warning", open_=False))
        parts.append("<p class='empty'>JS files referenced in code but returning 4xx — "
                     "potential dangling-resource takeover if an attacker can supply them via CDN/S3.</p>")
        parts.append("<table><thead><tr><th>Status</th><th>URL</th></tr></thead><tbody>")
        for d in dangling[:50]:
            parts.append(f"<tr><td><code>{html_escape(d.get('status','?'))}</code></td>"
                        f"<td><code>{html_escape(d.get('url',''))}</code></td></tr>")
        parts.append("</tbody></table>")
        parts.append(end_section())

    # ── Exposed source maps ──────────────────────────────────────────
    exposed_maps = parse_jsonl(results.get("exposed_maps_file"))
    if exposed_maps:
        parts.append(section("maps", "Exposed Source Maps",
                             len(exposed_maps), "warning", open_=True))
        parts.append("<p class='empty'>Source maps reachable in production reveal original "
                     "pre-minified source code, internal file paths, variable names, and secrets. "
                     "Original source files have been extracted to <code>sources/</code>.</p>")
        parts.append("<table><thead><tr>"
                     "<th>Map URL</th><th>Source file</th><th>Status</th><th>Discovery</th>"
                     "</tr></thead><tbody>")
        for m in exposed_maps[:50]:
            disc = m.get("discovery", "sourceMappingURL")
            disc_badge = ("<span class='badge warning'>blind probe</span>" if disc == "blind-probe"
                          else "<span class='badge neutral'>sourceMappingURL</span>")
            map_url_safe = html_escape(m.get('url', ''))
            url_copy_btn = (f"<button class='copy-btn' data-copy='{map_url_safe}' "
                            f"title='Copy map URL'>⧉</button>" if m.get('url') else "")
            row = (f"<tr><td><code>{map_url_safe}</code>{url_copy_btn}</td>"
                   + file_cell(m.get('source_file', ''))
                   + f"<td><code>{html_escape(str(m.get('status', '?')))}</code></td>"
                   + f"<td>{disc_badge}</td></tr>")
            parts.append(row)
            # Show discovered internal source paths (directory structure leak)
            src_paths = m.get("source_paths", [])
            if src_paths:
                paths_html = "".join(
                    f"<li><code>{html_escape(p)}</code></li>"
                    for p in src_paths[:20]
                )
                more = f"<li><em>… and {len(src_paths)-20} more</em></li>" if len(src_paths) > 20 else ""
                parts.append(f"<tr><td colspan='4'><details><summary>Internal source paths "
                             f"({len(src_paths)} file(s) — internal project structure)</summary>"
                             f"<ul>{paths_html}{more}</ul></details></td></tr>")
        parts.append("</tbody></table>")
        parts.append(end_section())

    # ── Wayback Machine historical maps ─────────────────────────────
    wayback_maps = parse_jsonl(results.get("wayback_maps_file"))
    if wayback_maps:
        wb_only   = [m for m in wayback_maps if not m.get("is_live")]
        wb_live   = [m for m in wayback_maps if m.get("is_live")]
        wb_badge  = "error" if wb_only else "warning"
        parts.append(section("wayback-maps", "Wayback Machine — Historical Source Maps",
                             len(wayback_maps), wb_badge, open_=True))
        parts.append(
            "<p class='empty'>Source maps discovered via the Wayback Machine CDX API. "
            "<strong>Archive-only maps</strong> were previously exposed in production — they may "
            "contain secrets or internal paths that have since been removed from the live site.</p>"
        )
        for group_label, group_items, group_badge, group_desc in [
            ("Archive-only (no longer live)", wb_only, "error",
             "These maps exist in the archive but returned non-200 on the live site — "
             "previously leaked, now removed. High priority."),
            ("Still live", wb_live, "warning",
             "These maps are reachable on both the archive and the live site."),
        ]:
            if not group_items:
                continue
            parts.append(sub(group_label, len(group_items), group_badge, open_=True))
            parts.append(f"<p class='empty'>{group_desc}</p>")
            parts.append("<table><thead><tr>"
                         "<th>Original URL</th><th>Captured</th>"
                         "<th>Archive link</th><th>Sources extracted</th>"
                         "</tr></thead><tbody>")
            for m in group_items[:50]:
                orig_url_safe = html_escape(m.get("url", ""))
                ts = m.get("timestamp", "")
                ts_fmt = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}" if len(ts) >= 8 else ts
                archive_url   = html_escape(m.get("archive_url", ""))
                orig_copy_btn = (
                    f"<button class='copy-btn' data-copy='{orig_url_safe}' "
                    f"title='Copy original URL'>⧉</button>" if m.get("url") else ""
                )
                parts.append(
                    f"<tr>"
                    f"<td><code>{orig_url_safe}</code>{orig_copy_btn}</td>"
                    f"<td><code>{html_escape(ts_fmt)}</code></td>"
                    f"<td><a href='{archive_url}' target='_blank' rel='noopener'>view ↗</a></td>"
                    f"<td>{m.get('sources_extracted', 0)}</td>"
                    f"</tr>"
                )
                src_paths = m.get("source_paths", [])
                if src_paths:
                    paths_html = "".join(
                        f"<li><code>{html_escape(p)}</code></li>"
                        for p in src_paths[:20]
                    )
                    more = (f"<li><em>… and {len(src_paths) - 20} more</em></li>"
                            if len(src_paths) > 20 else "")
                    parts.append(
                        f"<tr><td colspan='4'><details>"
                        f"<summary>Source paths ({len(src_paths)} file(s))</summary>"
                        f"<ul>{paths_html}{more}</ul></details></td></tr>"
                    )
            parts.append("</tbody></table>")
            parts.append(end_sub())
        parts.append(end_section())

    # ── Well-known files ─────────────────────────────────────────────
    wk_rows = parse_jsonl(results.get("well_known_file"))
    if wk_rows:
        leak_rows  = [r for r in wk_rows if r.get("category") == "leak"]
        disc_rows  = [r for r in wk_rows if r.get("category") == "discovery"]
        api_rows   = [r for r in wk_rows if r.get("category") == "api-doc"]
        policy_rows= [r for r in wk_rows if r.get("category") == "policy"]
        info_rows  = [r for r in wk_rows if r.get("category") == "info"]

        wk_badge = "error" if leak_rows else ("warning" if policy_rows else "success")
        parts.append(section("well-known", "Well-known Files",
                             f"{len(wk_rows)} files · "
                             f"{results.get('well_known_harvested', 0)} URLs harvested",
                             wk_badge, open_=True))
        parts.append("<p class='empty'>Probed conventional public paths "
                     "(robots.txt, sitemap.xml, .well-known/*, etc.). "
                     "<strong>Discovery</strong> files yielded URLs that were merged into the "
                     "endpoints list. <strong>Leak</strong> files shouldn't be exposed in production.</p>")

        # Trusted-domain notice if cross-origin policy files exist
        trust_count = results.get("well_known_trust_count", 0)
        if trust_count:
            parts.append(
                f"<div class='notice warn'>⚠ Cross-origin trust file(s) found — "
                f"{trust_count} domain(s) trusted via crossdomain.xml / clientaccesspolicy.xml. "
                f"See <code>well-known-trust.json</code>.</div>"
            )

        for label, items, bcls in [
            ("Leaks",       leak_rows,   "error"),
            ("Discovery",   disc_rows,   "success"),
            ("API docs",    api_rows,    "warning"),
            ("Policy",      policy_rows, "warning"),
            ("Info",        info_rows,   "neutral"),
        ]:
            if not items:
                continue
            parts.append(sub(label, len(items), bcls, open_=(bcls in ("error", "warning"))))
            parts.append("<table><thead><tr>"
                         "<th>Path</th><th>Description</th><th>Size</th><th>Harvested</th><th>Local</th>"
                         "</tr></thead><tbody>")
            for r in items[:100]:
                url_safe = html_escape(r.get("url", ""))
                harvested = r.get("harvested_paths", 0)
                harv_cell = f"<strong>{harvested}</strong> URL(s)" if harvested else "—"
                trusted = r.get("trusted_domains", [])
                if trusted:
                    trust_str = ", ".join(html_escape(d) for d in trusted[:5])
                    more = f" + {len(trusted) - 5} more" if len(trusted) > 5 else ""
                    harv_cell = f"trust: <code>{trust_str}{more}</code>"
                parts.append(
                    f"<tr>"
                    f"<td><a href='{url_safe}' target='_blank' rel='noopener'>"
                    f"<code>{html_escape(r.get('path', ''))}</code></a></td>"
                    f"<td>{html_escape(r.get('description', ''))}</td>"
                    f"<td>{r.get('size', 0):,}</td>"
                    f"<td>{harv_cell}</td>"
                    f"<td><code>{html_escape(r.get('local', ''))}</code></td>"
                    f"</tr>"
                )
            parts.append("</tbody></table>")
            parts.append(end_sub())
        parts.append(end_section())

    # ── Active recon ─────────────────────────────────────────────────
    recon_rows    = parse_jsonl(results.get("recon_summary_file"))
    recon_secrets = parse_jsonl(results.get("recon_secrets_file") or
                                (output_dir / "recon-secrets.json"))
    if recon_rows or recon_secrets:
        sec_count = len(recon_secrets)
        badge_cls = "error" if sec_count else "success"
        parts.append(section("active-recon", "Active Recon — Dorks + Broad Wayback",
                             f"{len(recon_rows)} files · {sec_count} secret hits",
                             badge_cls, open_=True))
        parts.append(
            "<p class='empty'>Files discovered via Google dorks (CSE API) and broad Wayback Machine "
            "queries across many extensions. JS files were fed into the main pipeline; other files "
            "land in <code>recon/</code> and are scanned for secrets.</p>"
        )

        # Group counts by extension
        if recon_rows:
            by_ext: dict[str, int] = {}
            by_bucket: dict[str, int] = {"js": 0, "map": 0, "recon": 0}
            for r in recon_rows:
                by_ext[r.get("ext", "?")] = by_ext.get(r.get("ext", "?"), 0) + 1
                by_bucket[r.get("bucket", "recon")] = by_bucket.get(r.get("bucket", "recon"), 0) + 1
            ext_summary = ", ".join(f"{c}×.{e}" for e, c in sorted(by_ext.items(),
                                                                    key=lambda kv: -kv[1])[:12])
            parts.append(f"<p><strong>Breakdown:</strong> "
                         f"{by_bucket.get('js', 0)} JS · "
                         f"{by_bucket.get('map', 0)} map · "
                         f"{by_bucket.get('recon', 0)} other<br>"
                         f"<code>{html_escape(ext_summary)}</code></p>")

            parts.append(sub("Downloaded files", len(recon_rows), "neutral", open_=False))
            parts.append("<table><thead><tr>"
                         "<th>URL</th><th>Type</th><th>Source</th><th>Size</th><th>Local</th>"
                         "</tr></thead><tbody>")
            for r in recon_rows[:200]:
                url_safe = html_escape(r.get("url", ""))
                src_badge = ("<span class='badge warning'>wayback</span>"
                             if r.get("source") == "wayback"
                             else "<span class='badge success'>live</span>")
                size = r.get("size", 0)
                parts.append(
                    f"<tr>"
                    f"<td><code>{url_safe}</code></td>"
                    f"<td><span class='badge neutral'>{html_escape(r.get('label', ''))}</span></td>"
                    f"<td>{src_badge}</td>"
                    f"<td>{size:,}</td>"
                    f"<td><code>{html_escape(r.get('local', ''))}</code></td>"
                    f"</tr>"
                )
            if len(recon_rows) > 200:
                parts.append(f"<tr><td colspan='5'><em>… and {len(recon_rows) - 200} "
                             f"more (see recon-summary.json)</em></td></tr>")
            parts.append("</tbody></table>")
            parts.append(end_sub())

        # Secrets found in recon files
        if recon_secrets:
            parts.append(sub("Secrets in recon files", len(recon_secrets), "error", open_=True))
            parts.append("<p class='empty'>Regex hits from <code>_SECRET_PATTERNS</code> "
                         "applied to non-JS recon downloads. Manually verify before reporting.</p>")
            parts.append("<table><thead><tr>"
                         "<th>File</th><th>Kind</th><th>Match</th><th>Context</th>"
                         "</tr></thead><tbody>")
            for s in recon_secrets[:200]:
                parts.append(
                    f"<tr>"
                    f"<td><code>{html_escape(s.get('file', ''))}</code></td>"
                    f"<td><span class='badge error'>{html_escape(s.get('kind', ''))}</span></td>"
                    f"<td><code>{html_escape(s.get('match', ''))}</code></td>"
                    f"<td><code>{html_escape(s.get('context', ''))}</code></td>"
                    f"</tr>"
                )
            parts.append("</tbody></table>")
            parts.append(end_sub())

        # Dork URLs for manual review
        dorks_file = results.get("dorks_file")
        if dorks_file and Path(dorks_file).exists():
            try:
                dorks_data = json.loads(Path(dorks_file).read_text())
            except Exception:
                dorks_data = []
            if dorks_data:
                parts.append(sub("Google dork URLs", len(dorks_data), "neutral", open_=False))
                parts.append("<p class='empty'>Click to open each query in Google. If "
                             "<code>GOOGLE_API_KEY</code> + <code>GOOGLE_CSE_ID</code> were set, "
                             "results were also fetched automatically.</p>")
                parts.append("<ul>")
                for d in dorks_data:
                    parts.append(
                        f"<li><a href='{html_escape(d.get('url', ''))}' target='_blank' "
                        f"rel='noopener'><code>{html_escape(d.get('query', ''))}</code></a> "
                        f"— {html_escape(d.get('purpose', ''))}</li>"
                    )
                parts.append("</ul>")
                parts.append(end_sub())

        parts.append(end_section())

    # ── JSON exposures ───────────────────────────────────────────────
    json_exp = parse_jsonl(results.get("json_exposures_file"))
    if json_exp:
        by_type = {}
        for j in json_exp: by_type.setdefault(j.get("type","unknown"),[]).append(j)
        parts.append(section("json-exp", "JSON File Exposures",
                             len(json_exp), "warning", open_=True))
        order = ["sensitive_config","config","swagger","openapi","unknown"]
        for t in order + [k for k in by_type if k not in order]:
            items = by_type.get(t)
            if not items: continue
            bcls = "error" if t == "sensitive_config" else ("warning" if t == "config" else "neutral")
            parts.append(sub(t, len(items), bcls, open_=True))
            parts.append("<table><thead><tr><th>URL</th><th>Sensitive keys</th><th>Size</th></tr></thead><tbody>")
            for j in items[:50]:
                keys = html_escape(", ".join(j.get("sensitive_keys",[]))) or "—"
                size = j.get("size",0)
                parts.append(f"<tr><td><code>{html_escape(j.get('url',''))}</code></td>"
                            f"<td><code>{keys}</code></td>"
                            f"<td>{f'{size:,}' if isinstance(size,int) else ''}</td></tr>")
            parts.append("</tbody></table>")
            parts.append(end_sub())
        parts.append(end_section())

    # ── Next steps ───────────────────────────────────────────────────
    parts.append(section("next-steps", "Next Steps", open_=True))
    parts.append("<div class='next-steps'><ol>")
    parts.append("<li>Triage <strong>auth-protected (401/403)</strong> live endpoints — obtain a valid JWT via /rest/user/login first</li>")
    parts.append("<li>Manually verify <strong>Semgrep innerHTML/outerHTML</strong> sinks — confirm user-controlled input reaches them</li>")
    parts.append("<li>Test all <strong>open redirect</strong> candidates with an external URL — chain with XSS for phishing</li>")
    parts.append("<li>Review <strong>HTTP Calls</strong> section for URLs not covered by the endpoint list (potential hidden API surface)</li>")
    parts.append("<li>Inspect <strong>extended secret matches</strong> in raw JS before any live validation (check ROE)</li>")
    parts.append("<li>Fuzz endpoints with body/query params using Burp Intruder or ffuf</li>")
    parts.append("</ol></div>")
    parts.append(end_section())

    # ── Footer ───────────────────────────────────────────────────────
    parts.append(f"<footer>Generated by jspect · {html_escape(now)}</footer>")
    parts.append("""
<script>
document.querySelectorAll('.copy-btn').forEach(function(btn) {
    btn.addEventListener('click', function() {
        var text = btn.getAttribute('data-copy');
        if (!text) return;
        navigator.clipboard.writeText(text).then(function() {
            btn.textContent = 'copied';
            btn.classList.add('copied');
            setTimeout(function() {
                btn.textContent = '⧉';
                btn.classList.remove('copied');
            }, 1500);
        }).catch(function() {
            /* fallback for non-https / older browsers */
            var ta = document.createElement('textarea');
            ta.value = text;
            ta.style.position = 'fixed';
            ta.style.opacity = '0';
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            document.body.removeChild(ta);
            btn.textContent = 'copied';
            btn.classList.add('copied');
            setTimeout(function() {
                btn.textContent = '⧉';
                btn.classList.remove('copied');
            }, 1500);
        });
    });
});
</script>
</div></body></html>""")

    report_path.write_text("\n".join(parts), encoding="utf-8", errors="replace")
    Log.info(f"    {C.GREEN}[+]{C.RESET} Report written to {report_path}")
    return report_path


# ---------- Main ----------

class HelpfulArgumentParser(argparse.ArgumentParser):
    """Print full help on any argparse error (missing arg, bad value, etc.)."""

    def error(self, message):
        sys.stderr.write(f"\n{C.RED}error:{C.RESET} {message}\n\n")
        self.print_help(sys.stderr)
        sys.exit(2)


def main():
    global THREAD_POOL_WORKERS         # may be overridden by --threads
    global MAX_ENDPOINTS_TO_VALIDATE   # may be overridden by --max-endpoints
    print_banner()

    parser = HelpfulArgumentParser(
        prog="jspect",
        description="Automated JS analysis pipeline (Katana → JSluice → Semgrep → TruffleHog)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  # URL mode — crawl and analyse a live target:\n"
            "  ./jspect.py -u https://target.com\n"
            "  ./jspect.py -u https://target.com -H \"Cookie: session=abc123\"\n"
            "  ./jspect.py -u https://target.com -H \"Authorization: Bearer eyJ...\" -d 6\n"
            "  ./jspect.py -u https://target.com --verify-secrets    # ROE permitting\n"
            "  ./jspect.py -u https://target.com --no-beautify       # skip prettifier\n"
            "  ./jspect.py -u https://target.com --discover-levels 0 # disable nested JS\n"
            "\n"
            "  # Dir mode — analyse a local source tree directly:\n"
            "  ./jspect.py --dir /path/to/NodeGoat\n"
            "\n"
            "  # Combined — static source analysis + live endpoint probing:\n"
            "  ./jspect.py --dir /path/to/NodeGoat -u http://localhost:4000\n"
            "  ./jspect.py --dir /path/to/NodeGoat -u http://localhost:4000 \\\n"
            "      -H \"Cookie: connect.sid=s%3Axxx...\"\n"
        ),
    )
    parser.add_argument("-u", "--url", default=None,
                        help="Target URL to crawl (required unless --dir is used)")
    parser.add_argument("--dir", default=None, metavar="PATH",
                        help="Analyze a local JS source directory directly (skips crawl/download). "
                             "Use with -u to set the report target label, e.g. "
                             "--dir /path/to/app -u http://localhost:4000")
    parser.add_argument("-H", "--header", action="append", default=[], metavar="HEADER",
                        help="Header for auth, e.g. \"Cookie: session=abc\" or \"Authorization: Bearer xxx\". Repeatable.")
    parser.add_argument("-o", "--output", default=None, metavar="DIR",
                        help="Output directory (default: auto-timestamped)")
    parser.add_argument("-d", "--depth", type=int, default=5, metavar="N",
                        help="Katana crawl depth (default 5)")
    parser.add_argument("--rate-limit", type=int, default=50, metavar="N",
                        help="Katana rate limit per second (default 50)")
    parser.add_argument("--max-duration", type=int, default=10, metavar="MIN",
                        help="Katana crawl time cap in minutes (default 10)")
    parser.add_argument("--discover-levels", type=int, default=2, metavar="N",
                        help="Multi-level JS discovery depth (default 2, 0 to disable)")
    parser.add_argument("--no-beautify", action="store_true",
                        help="Skip the JS beautification stage")
    # Headless: kept as an opt-IN flag because Katana's `-headless` mode is
    # marked "experimental" upstream and hangs silently on macOS in our testing
    # (Chrome itself works fine; the Katana integration is the culprit).
    # On Linux/Docker it can still be useful for SPA-heavy targets.
    parser.add_argument("--headless", action="store_true",
                        help="Run Katana in headless Chrome mode (experimental upstream; "
                             "hangs silently on macOS — recommended only on Linux/Docker)")
    # Back-compat alias — the flag was previously --no-headless and defaulted to headless=ON.
    # Now we default to headless=OFF since most of our test platforms can't use it.
    parser.add_argument("--no-headless", action="store_true",
                        help=argparse.SUPPRESS)   # deprecated, kept for back-compat
    parser.add_argument("--verify-secrets", action="store_true",
                        help="Run TruffleHog with --only-verified (makes real API calls — check ROE)")
    parser.add_argument("--proxy", default=None, metavar="URL",
                        help="HTTP/SOCKS proxy for every outbound request "
                             "(e.g. http://127.0.0.1:8080 for Burp, socks5://127.0.0.1:9050 for Tor). "
                             "Sets HTTP(S)_PROXY env vars and passes -proxy to Katana.")
    parser.add_argument("--proxy-insecure", action="store_true",
                        help="Skip TLS verification on the proxy connection "
                             "(needed for Burp/mitmproxy with self-signed certs)")
    parser.add_argument("--threads", type=int, default=None, metavar="N",
                        help=f"Concurrent workers for JS download + endpoint probing "
                             f"(default {THREAD_POOL_WORKERS}). Use 1 to be polite to small targets.")
    parser.add_argument("--max-endpoints", type=int, default=None, metavar="N",
                        help=f"Cap how many endpoints Stage 5 live-validates "
                             f"(default {MAX_ENDPOINTS_TO_VALIDATE}). Use 0 for unlimited. "
                             f"When the cap is hit, API-shaped paths are prioritized over content URLs.")
    parser.add_argument("--no-wayback", action="store_true",
                        help="Skip Wayback Machine historical map discovery (Stage 5d)")
    parser.add_argument("--active-recon", action="store_true",
                        help="Aggressive file discovery: Google dorks + broad Wayback queries "
                             "across many file types (.js .map .json .yml .env .config .txt .bak …). "
                             "Set GOOGLE_API_KEY + GOOGLE_CSE_ID env vars to auto-fetch dork results.")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="Increase verbosity (-v = verbose, -vv = debug)")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Suppress non-essential output")

    # Show full help when run with no arguments at all
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    # Validate: need at least --url or --dir
    if not args.url and not args.dir:
        parser.error("one of --url or --dir is required")

    # Optional concurrency override — let callers throttle to be polite to small targets.
    if args.threads is not None:
        if args.threads < 1:
            parser.error("--threads must be >= 1")
        THREAD_POOL_WORKERS = args.threads
    # Optional endpoint-validation cap override.
    if args.max_endpoints is not None:
        if args.max_endpoints < 0:
            parser.error("--max-endpoints must be >= 0 (0 = unlimited)")
        # 0 → effectively infinite (large enough to never hit)
        MAX_ENDPOINTS_TO_VALIDATE = args.max_endpoints if args.max_endpoints > 0 else 10**9

    # Optional proxy: set env vars so urllib (Python stages) and child processes
    # (Semgrep, Retire.js, TruffleHog, etc.) all route through it. Katana is
    # handled separately via its own -proxy arg in run_katana().
    if args.proxy:
        p = args.proxy.strip()
        os.environ["HTTP_PROXY"]  = p
        os.environ["HTTPS_PROXY"] = p
        os.environ["http_proxy"]  = p
        os.environ["https_proxy"] = p
        Log.info(f"    {C.DIM}↳ proxy: all HTTP requests routed through {p}{C.RESET}")
        if args.proxy_insecure:
            # urllib + our permissive_ssl_context() already disable cert verification
            # on the target side; this env var also tells child tools that mostly
            # respect it (requests, httpx, etc.) to skip proxy TLS validation.
            os.environ["PYTHONHTTPSVERIFY"] = "0"
            os.environ["CURL_CA_BUNDLE"]    = ""
            os.environ["REQUESTS_CA_BUNDLE"] = ""

    if args.dir and not Path(args.dir).is_dir():
        parser.error(f"--dir path does not exist or is not a directory: {args.dir}")

    # When --dir is used, --url becomes a label only (defaults to the dir path)
    target_label = args.url or f"file://{Path(args.dir).resolve()}"

    # Configure logging level
    if args.quiet:
        Log.set_level(0)
    else:
        Log.set_level(1 + args.verbose)

    if args.dir:
        print(f"{C.BOLD}Mode:{C.RESET}         local directory")
        print(f"{C.BOLD}Dir:{C.RESET}          {args.dir}")
        print(f"{C.BOLD}Label:{C.RESET}        {target_label}")
    else:
        print(f"{C.BOLD}Target:{C.RESET}       {args.url}")
        print(f"{C.BOLD}Auth headers:{C.RESET} {len(args.header)}")
        print(f"{C.BOLD}Depth:{C.RESET}        {args.depth}")
    print(f"{C.BOLD}Verify:{C.RESET}       {'yes (real API calls)' if args.verify_secrets else 'no'}")
    Log.verbose(f"Platform:     {platform_info()}")
    Log.verbose(f"Log level:    {Log.level} ({'quiet' if Log.level == 0 else 'normal' if Log.level == 1 else 'verbose' if Log.level == 2 else 'debug'})")
    print()
    available = check_environment()

    # Output dir
    if args.url:
        host = urlparse(args.url).hostname or "target"
    else:
        host = Path(args.dir).name or "local"
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_dir = Path(args.output) if args.output else Path(f"jspect-{host}-{timestamp}")
    output_dir.mkdir(parents=True, exist_ok=True)
    Log.info(f"\nOutput: {output_dir}")
    Log.verbose(f"absolute: {output_dir.resolve()}")

    results = {}

    # ── LOCAL DIRECTORY MODE ─────────────────────────────────────────────────
    # Skip Stages 1 & 2 (crawl + download). Use the supplied directory directly.
    if args.dir:
        stage_header("1-2", "Crawl + Download (skipped — local directory mode)")
        Log.info(f"    [-] Using local source directory: {args.dir}")
        js_clean = output_dir / "js-clean"
        js_clean.mkdir(exist_ok=True)
        # Symlink or copy every *.js file found under --dir into js-clean
        src_root = Path(args.dir)
        copied = 0
        for jsfile in sorted(src_root.rglob("*.js")):
            # Skip node_modules and hidden dirs
            parts = jsfile.parts
            if any(p.startswith(".") or p == "node_modules" for p in parts):
                continue
            # Flatten with a sanitised name so all files sit in js-clean/
            rel = jsfile.relative_to(src_root)
            flat_name = "__".join(rel.parts)  # e.g. app__routes__index.js
            dest = js_clean / flat_name
            if not dest.exists():
                shutil.copy2(jsfile, dest)
                copied += 1
        Log.info(f"    {C.GREEN}[+]{C.RESET} Copied {copied} JS file(s) from {src_root}")
        results["js_count"] = copied
        results["url_count"] = 0  # no crawl

        # Beautify still runs — source files may still benefit
        if not args.no_beautify:
            beautify_js(js_clean)

        # Skip source-map recovery (source is already unminified)
        analysis_target = js_clean
        results["source_maps"] = False

    # ── NORMAL URL MODE ──────────────────────────────────────────────────────
    else:
        # Resolve headless choice:
        # - Default is OFF (Katana's headless integration hangs silently on macOS).
        # - --headless explicitly opts in.
        # - --no-headless is the legacy form (still honored).
        headless_requested = args.headless and not args.no_headless
        if headless_requested and platform.system() == "Darwin":
            Log.warn("--headless on macOS hits a known upstream Katana hang; "
                     "consider running without it (HTML <script> scrape fallback "
                     "covers most non-SPA sites).")
        # Stage 1
        katana_out, url_count = run_katana(
            args.url, output_dir, args.header, args.depth, args.rate_limit,
            headless=headless_requested, max_duration=args.max_duration,
            proxy=args.proxy,
        )
        if not katana_out:
            # Don't bail — well-known, active-recon, and Wayback don't need crawl
            # output. WAF-protected targets, Cloudflare-challenge sites, and bots-banned
            # endpoints frequently fail Katana but still expose plenty via recon.
            Log.warn("Katana produced no output — continuing with recon stages only "
                     "(well-known / active-recon / Wayback are still useful)")
            url_count = 0
        results["url_count"] = url_count

        # Stage 2 — always try download_js, even when Katana yielded nothing.
        # download_js has a built-in homepage fallback (reads katana-target.txt)
        # that lets us still discover scripts via direct fetch of the seed URL.
        if not katana_out:
            # Synthesize an empty katana-out.txt so download_js can run its
            # HTML scrape / homepage-fetch fallbacks.
            katana_out = output_dir / "katana-out.txt"
            if not katana_out.exists():
                katana_out.write_text("", encoding="utf-8")
        js_clean = download_js(katana_out, output_dir, args.header)
        if not js_clean:
            # No JS downloaded directly — fall back to an empty js-clean dir so
            # active-recon / well-known / Wayback can still run and possibly
            # populate it. Skip JS-dependent intermediate stages instead of bailing.
            Log.warn("No JS files downloaded from crawl — continuing with recon stages "
                     "(active-recon / Wayback may still discover JS files)")
            js_clean = output_dir / "js-clean"
            js_clean.mkdir(exist_ok=True)
        results["js_count"] = len(list(js_clean.glob("*.js")))

        # Stage 2b — Multi-level JS discovery (URL mode only)
        dangling_file = discover_nested_js(
            js_clean, output_dir, args.header, args.url,
            max_levels=args.discover_levels,
        )
        results["dangling_file"] = dangling_file
        if dangling_file:
            results["dangling_count"] = count_nonempty_lines(dangling_file)
        # Refresh JS count after multi-level discovery
        results["js_count"] = len(list(js_clean.glob("*.js")))

        # Stage 2c — Beautify minified JS (URL mode only; dir mode does it above)
        if not args.no_beautify:
            beautify_js(js_clean)

        # Stage 4b — Active recon (Google dorks + broad Wayback) — opt-in via --active-recon
        if args.active_recon:
            recon = active_recon_discovery(args.url, output_dir, args.header, js_clean)
            results.update(recon)
            # Beautify any new JS files that were just downloaded
            if recon.get("recon_js_added", 0) and not args.no_beautify:
                beautify_js(js_clean)
            # Refresh JS count to reflect new files in the pipeline
            results["js_count"] = len(list(js_clean.glob("*.js")))

        # Stage 3 — Source map recovery (URL mode only)
        sources = recover_source_maps(js_clean, output_dir, available, args.url, args.header)
        results["source_maps"] = bool(sources)
        # Prefer source maps for downstream analysis when available
        analysis_target = sources if sources else js_clean
    # ── end URL-mode block ───────────────────────────────────────────────────

    # Stage 4 — JSluice
    endpoints, secrets = run_jsluice(analysis_target, output_dir)
    results["endpoints_file"] = endpoints
    results["secrets_file"] = secrets
    if endpoints:
        results["endpoint_count"] = count_nonempty_lines(endpoints)
    if secrets:
        results["jsluice_secrets"] = count_nonempty_lines(secrets)

    # Stage 4c — Well-known files probe (URL mode only — needs a base URL)
    # Always-on passive recon: every probed path is public by convention.
    if args.url:
        wk = discover_well_known(args.url, output_dir, args.header, endpoints)
        results.update(wk)
        # Adopt newly-created endpoints file (well-known may have written it from
        # scratch when jsluice produced nothing — e.g. WordPress sites with no JS).
        new_ep = wk.get("endpoints_file_after_wk")
        if new_ep and (not endpoints or not endpoints.exists()):
            endpoints = new_ep
            results["endpoints_file"] = endpoints
        if endpoints and endpoints.exists():
            results["endpoint_count"] = count_nonempty_lines(endpoints)

    # Stage 5 — Live endpoint validation (skip in local dir mode — no base URL to probe)
    if args.url:
        live_file = validate_endpoints(args.url, endpoints, output_dir, args.header)
    else:
        stage_header("5", "Live endpoint validation (skipped — local directory mode)")
        Log.info("    [-] No base URL supplied; pass -u http://host to enable probing")
        live_file = None
    results["live_endpoints_file"] = live_file
    if live_file:
        results["live_count"] = count_nonempty_lines(live_file)

    # Stage 5b — Static metadata analysis (maps, JSON, comments)
    meta = static_metadata_analysis(js_clean, output_dir, target_label, args.header)
    results["exposed_maps_file"] = meta["maps_file"]
    results["json_exposures_file"] = meta["json_file"]
    results["swagger_endpoints_file"] = meta["swagger_endpoints_file"]
    results["comments_file"] = meta["comments_file"]
    results["exposed_maps_count"] = meta["exposed_maps"]
    results["json_exposures_count"] = meta["json_findings"]
    results["swagger_endpoints_count"] = meta["swagger_endpoints"]
    results["comments_count"] = meta["comments"]

    # Merge Swagger-discovered endpoints into the main endpoints file
    swagger_file = meta.get("swagger_endpoints_file")
    if swagger_file and swagger_file.exists() and endpoints and endpoints.exists():
        merged = 0
        try:
            with endpoints.open("a", encoding="utf-8") as dst:
                with swagger_file.open(encoding="utf-8", errors="replace") as src:
                    for line in src:
                        if line.strip():
                            dst.write(line)
                            merged += 1
            results["endpoint_count"] = count_nonempty_lines(endpoints)
            Log.verbose(f"merged {merged} Swagger endpoint(s) into {endpoints.name}")
        except OSError as e:
            Log.warn(f"swagger merge failed: {e}")

    # Stage 5d — Wayback Machine historical map discovery (URL mode only)
    if args.url and not args.no_wayback:
        wb = query_wayback_maps(args.url, output_dir, args.header)
    else:
        if args.no_wayback:
            stage_header("5d", "Wayback Machine historical map discovery (skipped via --no-wayback)")
        wb = {"wayback_maps_file": None, "wayback_maps_count": 0, "wayback_only_count": 0}
    results["wayback_maps_file"]  = wb["wayback_maps_file"]
    results["wayback_maps_count"] = wb["wayback_maps_count"]
    results["wayback_only_count"] = wb["wayback_only_count"]

    # Stage 5c — HTTP call extraction + extended secrets
    http_calls_file, secrets_ext_file = extract_http_calls_and_secrets(js_clean, output_dir)
    results["http_calls_file"] = http_calls_file
    results["secrets_ext_file"] = secrets_ext_file
    if http_calls_file:
        results["http_calls_count"] = count_nonempty_lines(http_calls_file)
    if secrets_ext_file:
        results["secrets_ext_count"] = count_nonempty_lines(secrets_ext_file)

    # Stage 6 — Semgrep
    semgrep_file = run_semgrep(analysis_target, output_dir, available)
    results["semgrep_file"] = semgrep_file
    if semgrep_file:
        try:
            sem_data = json.loads(semgrep_file.read_text(encoding="utf-8", errors="replace"))
            sem_results = sem_data.get("results", [])
            results["semgrep_total"] = len(sem_results)
            results["semgrep_error"] = sum(
                1 for r in sem_results
                if r.get("extra", {}).get("severity") == "ERROR"
            )
            results["semgrep_timeouts"] = sem_data.get("_timeout_count", 0)
        except Exception:
            pass

    # Stage 7 — Retire.js
    retire_file = run_retire(analysis_target, output_dir)
    results["retire_file"] = retire_file
    if retire_file:
        try:
            data = json.loads(retire_file.read_text(encoding="utf-8", errors="replace"))
            entries = data.get("data", []) if isinstance(data, dict) else data
            vuln_count = 0
            affected = set()
            for entry in entries:
                for r in entry.get("results", []):
                    if r.get("vulnerabilities"):
                        affected.add(f"{r.get('component')}@{r.get('version')}")
                        vuln_count += len(r.get("vulnerabilities", []))
            results["retire_vuln_libs"] = len(affected)
            results["retire_vulns"] = vuln_count
        except Exception:
            pass

    # Stage 8 — TruffleHog
    th_file = run_trufflehog(analysis_target, output_dir, available, args.verify_secrets)
    results["trufflehog_file"] = th_file
    results["th_verified"] = args.verify_secrets
    if th_file:
        results["th_candidates"] = count_nonempty_lines(th_file)

    # Stage 9 — Report
    generate_report(target_label, output_dir, results)

    Log.info("\n" + f"{C.BOLD}{C.GREEN}{'═' * 60}{C.RESET}")
    Log.info(f"{C.BOLD}{C.GREEN}  Done.{C.RESET}")
    Log.info(f"{C.BOLD}{C.GREEN}{'═' * 60}{C.RESET}")

    # Quick "where to look first" summary — only show if there's something actionable
    priorities = []
    if results.get("semgrep_error", 0) > 0:
        priorities.append(f"{results['semgrep_error']} Semgrep ERROR finding(s) — likely dangerous sinks")
    if results.get("retire_vuln_libs", 0) > 0:
        priorities.append(f"{results['retire_vuln_libs']} vulnerable librar(ies) with known CVEs")
    if results.get("exposed_maps_count", 0) > 0:
        priorities.append(f"{results['exposed_maps_count']} exposed source map(s) — production misconfig")
    if results.get("json_exposures_count", 0) > 0:
        priorities.append(f"{results['json_exposures_count']} JSON exposure(s) — config files / API docs")
    if results.get("dangling_count", 0) > 0:
        priorities.append(f"{results['dangling_count']} dangling JS reference(s) — potential takeover")
    if results.get("secrets_ext_count", 0) > 0:
        priorities.append(f"{results['secrets_ext_count']} extended secret candidate(s) — review secrets-extended.json")
    if results.get("http_calls_count", 0) > 0:
        priorities.append(f"{results['http_calls_count']} HTTP call reference(s) extracted — see http-calls.json")
    if results.get("wayback_only_count", 0) > 0:
        priorities.append(
            f"{results['wayback_only_count']} Wayback-only map(s) — previously exposed, now removed; "
            f"check sources/ for leaked code/secrets"
        )
    if results.get("well_known_leaks", 0) > 0:
        priorities.append(
            f"{results['well_known_leaks']} leak(s) at well-known paths "
            f"(.git/.env/.DS_Store/manifests) — see well-known/"
        )
    if results.get("well_known_trust_count", 0) > 0:
        priorities.append(
            f"{results['well_known_trust_count']} cross-origin trusted domain(s) "
            f"via crossdomain/clientaccesspolicy — review well-known-trust.json"
        )
    if results.get("well_known_harvested", 0) > 0:
        priorities.append(
            f"{results['well_known_harvested']} URL(s) harvested from robots/sitemap "
            f"and merged into endpoints"
        )
    if results.get("recon_secrets_found", 0) > 0:
        priorities.append(
            f"{results['recon_secrets_found']} secret(s) found in active-recon files — see "
            f"recon-secrets.json and recon/ directory"
        )
    if results.get("recon_downloaded", 0) > 0:
        priorities.append(
            f"{results['recon_downloaded']} extra file(s) pulled by active-recon "
            f"(+{results.get('recon_js_added', 0)} JS, "
            f"+{results.get('recon_map_added', 0)} maps into pipeline)"
        )

    if priorities:
        Log.info(f"\n{C.BOLD}Priority leads:{C.RESET}")
        for p in priorities[:5]:
            Log.info(f"  • {p}")

    Log.info(f"\n{C.BOLD}Report:{C.RESET}        {output_dir / 'report.html'}")
    Log.info(f"{C.BOLD}All artifacts:{C.RESET} {output_dir}")


if __name__ == "__main__":
    main()