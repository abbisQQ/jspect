# jspect — JavaScript Analysis Pipeline

Automated multi-stage static analysis tool for web application penetration testing. Crawls a live target or reads local source files, extracts every JavaScript asset, and runs a full analysis chain: endpoint discovery, secret detection, SAST, and vulnerable library detection — all rolled into a single dark-themed HTML report.

---

## Quick Start

```bash
# Analyse a live target — default settings (10 threads)
python3 jspect.py -u http://localhost:3000

# Polite single-thread run against a small target
python3 jspect.py -u https://target.com \
    --threads 1 --rate-limit 5 --max-duration 2

# Full recon — Google dorks + broad Wayback + well-known files
python3 jspect.py -u https://target.com \
    --active-recon --max-endpoints 1500

# Authenticated scan
python3 jspect.py -u https://target.com \
    -H "Cookie: session=..." \
    -H "Authorization: Bearer eyJ..."

# Analyse local source code (e.g. NodeGoat) — no network at all
python3 jspect.py --dir /path/to/NodeGoat

# Both: full static analysis + live endpoint probing, authenticated
python3 jspect.py \
    --dir /path/to/NodeGoat \
    -u http://localhost:4000 \
    -H "Cookie: connect.sid=s%3Axxx..."
```

The report is written to a timestamped directory in the current folder:
```
jspect-target-com-20260518-103803/report.html
```

---

## Dependencies

Install all tools before running. The script checks for each at startup and skips stages for missing tools (it will not crash).

| Tool | Install | Used for |
|------|---------|----------|
| **Katana** | `go install github.com/projectdiscovery/katana/cmd/katana@latest` | Crawling |
| **JSluice** | `go install github.com/BishopFox/jsluice/cmd/jsluice@latest` | Endpoint/secret extraction |
| **Semgrep** | `pip install semgrep` | SAST / DOM sink detection |
| **Retire.js** | `npm install -g retire` | Vulnerable library fingerprinting |
| **TruffleHog** | `brew install trufflehog` | Secret/credential detection |
| **jsbeautifier** | `pip install jsbeautifier` | Minified JS expansion |
| **sourcemapper** | `go install github.com/denandz/sourcemapper@latest` | Webpack source map unpacking |
| **unwebpack-sourcemap** | `npm install -g unwebpack-sourcemap` | Source map recovery (fallback) |

> **Go tools** require `$GOPATH/bin` (usually `~/go/bin`) to be in your `PATH`. Add this to your shell profile:
> ```bash
> export PATH="$HOME/go/bin:$PATH"
> ```

The Python deps are installable in one shot:
```bash
pip install -r requirements.txt
```

### Optional: better source-map recovery via `mapperplus`

For deeply-bundled webpack apps where the built-in extractor and `unwebpack-sourcemap` come up short, you can drop the [`mapperplus`](https://github.com/Zierax/MapperPlus) helper next to the script:

```bash
git clone https://github.com/Zierax/MapperPlus.git ./mapperplus
```

The tool auto-detects `./mapperplus/mapperplus.py` and prefers it. If it's missing, the tool falls back gracefully — nothing breaks.

### Optional: auto-fetch Google dork results (`--active-recon`)

Set two env vars to enable automatic fetching of Google dork results via the
Custom Search JSON API (free tier: 100 queries/day):

```bash
export GOOGLE_API_KEY="..."
export GOOGLE_CSE_ID="..."
```

When unset, `--active-recon` still generates and saves the clickable dork URLs to `dorks.json` for manual use.

---

## Operating Modes

### URL Mode — Live Target

Crawls the target with a headless browser (Katana), downloads all JavaScript responses, then analyses them.

```bash
python3 jspect.py -u https://target.com
```

**Use this when:** You only have access to the running application (black-box test).

---

### Dir Mode — Local Source Tree

Skips crawl and download entirely. Copies every `*.js` file found under the given directory (excluding `node_modules`) into the analysis corpus, then runs all analysis stages.

```bash
python3 jspect.py --dir /path/to/source
```

**Use this when:** You have the source code (code review, open-source audit, cloned repo).

> Express/Node.js routes, data-layer files, config files, and server-side logic are all included — nothing is excluded because it "doesn't run in a browser."

---

### Combined Mode — Best of Both

Provides the full source analysis of `--dir` plus live endpoint probing against the running application. Pass both flags together.

```bash
python3 jspect.py \
    --dir /path/to/NodeGoat \
    -u http://localhost:4000
```

The `-u` value is used as:
1. The base URL for live endpoint probing (Stage 5)
2. The report title / target label

---

## Authentication

Pass session cookies or auth headers with `-H`. The flag is repeatable.

```bash
# Session cookie (most common for web apps)
python3 jspect.py -u http://localhost:4000 \
    -H "Cookie: connect.sid=s%3Axxx..."

# Bearer token
python3 jspect.py -u https://api.example.com \
    -H "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9..."

# Multiple headers
python3 jspect.py -u https://target.com \
    -H "Cookie: session=abc" \
    -H "X-CSRF-Token: xyz"
```

### Getting the session cookie

```bash
# Login and capture the cookie
curl -c /tmp/cookies.txt -X POST http://localhost:4000/login \
    -d "userName=tester&password=tester" \
    -H "Content-Type: application/x-www-form-urlencoded" -L -o /dev/null

# Verify it works on a protected route
curl -b /tmp/cookies.txt http://localhost:4000/dashboard -o /dev/null -w "%{http_code}\n"

# Use it with the tool
COOKIE=$(grep connect.sid /tmp/cookies.txt | awk '{print $6"="$7}')
python3 jspect.py -u http://localhost:4000 -H "Cookie: $COOKIE"
```

---

## Pipeline Stages

| Stage | Name | Description |
|-------|------|-------------|
| 1 | Katana crawl | Crawls the target; discovers page + JS URLs. URL mode only. |
| 2 | JS download | Fetches and deduplicates all JS files into a local corpus. URL mode only. **Falls back to scraping `<script src>` from HTML pages** when Katana finds few/no JS URLs (covers WordPress, DLE, FusionCMS, CodeIgniter, etc.). Final fallback: fetch the seed URL homepage directly. |
| 2b | Nested JS discovery | Follows JS-referenced imports up to `--discover-levels` deep. URL mode only. |
| 2c | Beautification | Expands minified JS for readability using jsbeautifier. |
| 3 | Source-map recovery | Unpacks webpack `.map` files to reveal original source. URL mode only. |
| 4 | JSluice | AST-based endpoint and secret extraction. Webpack module-import noise (`./auth/index.js`, etc.) is filtered out before endpoints land in `endpoints.json`. |
| 4b | Active recon | Generates Google dorks (saved to `dorks.json`; auto-fetched via Google CSE API if `GOOGLE_API_KEY`+`GOOGLE_CSE_ID` env vars are set) and runs a broad Wayback CDX sweep across ~20 file extensions. URL mode + `--active-recon` only. |
| 4c | Well-known files | Probes 43 conventional paths (robots.txt, sitemap.xml, .well-known/*, crossdomain.xml, .git/config, .env, package.json, Gemfile, swagger.json, etc.). Parses robots/sitemap chains recursively. Validates leak findings with per-path content-shape checks so SPA catch-all 200s aren't reported as fake leaks. |
| 5 | Live endpoint validation | HTTP probes all discovered endpoints; records status codes, auth requirements. Capped by `--max-endpoints N` (default 500); priority order: API/auth paths first, short paths next, deep content last. |
| 5b | Static metadata | Checks for exposed `.map` files (with **blind-probe** for maps that have no `sourceMappingURL` comment), API docs, Swagger specs, developer comments. Extracts `sourcesContent` from any map found, with safe filename truncation. |
| 5c | HTTP calls + secrets | Regex scan for fetch/axios/XHR/Express routes; JWT, AWS, API key patterns, with Shannon-entropy gating on hex/UUID candidates. |
| 5d | Wayback maps | Queries Wayback Machine CDX API for historically captured `*.js.map` files. Highlights maps that exist only in the archive (previously exposed, now removed). Skip with `--no-wayback`. |
| 6 | Semgrep SAST | DOM XSS sinks, `eval()` (true global eval, not `obj.eval()` method calls), open redirects, Angular `innerHTML`, cookie misconfig. Bundles ~80 local rules. |
| 7 | Retire.js | Fingerprints JavaScript libraries and flags known CVEs. |
| 8 | TruffleHog | Entropy-based secret and credential detection. |
| 9 | HTML report | Dark-themed, collapsible, self-contained single-file report. Cross-references live-probe status when ranking open-redirect candidates. |

---

## All Options

```
python3 jspect.py --help
```

| Flag | Default | Description |
|------|---------|-------------|
| `-u URL` | — | Target URL (required unless `--dir` is used) |
| `--dir PATH` | — | Local JS source directory (skips crawl/download) |
| `-H HEADER` | — | Auth header, e.g. `"Cookie: session=abc"`. Repeatable. |
| `-o DIR` | auto | Output directory name (default: timestamped) |
| `-d N` | `5` | Katana crawl depth |
| `--rate-limit N` | `50` | Katana requests/second |
| `--max-duration MIN` | `10` | Katana crawl time cap in minutes |
| `--discover-levels N` | `2` | Multi-level nested JS import discovery depth (0 = off) |
| `--threads N` | `10` | Concurrent workers for JS download + endpoint probing. Use `1` to be polite to small targets. |
| `--max-endpoints N` | `500` | Cap Stage 5 live-validation. `0` = unlimited. When the cap is hit, API/short paths are prioritized over deep content URLs. The report surfaces the truncation explicitly. |
| `--active-recon` | off | Aggressive discovery: Google dorks (saved + optionally auto-fetched if `GOOGLE_API_KEY`+`GOOGLE_CSE_ID` env vars exist) + broad Wayback CDX queries across `.js .map .json .yml .env .config .txt .bak …`. |
| `--no-wayback` | off | Skip Stage 5d (Wayback historical map discovery). |
| `--no-beautify` | off | Skip JS beautification (faster, less readable output) |
| `--headless` | off | Run Katana in headless Chrome mode (**experimental upstream — hangs silently on macOS**; recommended only on Linux/Docker). |
| `--verify-secrets` | off | Run TruffleHog with `--only-verified` (makes real API calls — check ROE) |
| `-v` / `-vv` | normal | Verbose / debug logging |
| `-q` | off | Quiet mode — suppress non-essential output |

---

## Report Sections

The HTML report has a sticky navigation bar with color-coded links (orange = findings present, red = errors). Every section is collapsible.

| Section | What it shows |
|---------|---------------|
| **Summary** | Run metadata, JS file count, tool availability |
| **Endpoints** | All URLs extracted by JSluice from JS source |
| **Live Endpoints** | HTTP probe results: status codes, auth-protected routes, server errors |
| **HTTP Calls** | `fetch`, `axios`, XHR, Angular HttpClient, Express routes extracted from source |
| **Secrets** | JSluice findings + TruffleHog candidates + extended regex matches (JWT, AWS, API keys) |
| **Semgrep** | SAST findings grouped by severity and rule |
| **Libraries** | Retire.js output: library versions and CVE list |
| **Comments** | Developer comments with credential mentions and TODOs |
| **Next Steps** | Prioritised list of suggested follow-up actions |

Artifact files (JSON) for each stage are written alongside the report for use with other tools.

---

## Recommended Test Targets

These apps are intentionally vulnerable and well-suited for testing this tool:

| App | Mode | Why |
|-----|------|-----|
| **OWASP Juice Shop** | URL | Angular SPA; tests DOM XSS, Angular `innerHTML` patterns, webpack bundles |
| **OWASP NodeGoat** | Dir + URL | Express/Node.js; `eval(req.body)` RCE, NoSQL injection, open redirect, auth flaws |
| **DVWA** | URL | Classic DOM XSS sinks (`innerHTML`, `eval`, `document.write`) |
| **OWASP WebGoat** | URL | Broad OWASP Top 10 coverage including client-side |
| **OWASP crAPI** | URL + Dir | REST API with Angular frontend; JWT abuse, BOLA |
| **DVNA** | Dir | Node.js with Sequelize; hardcoded secrets in JS config files |

### Starting NodeGoat with Docker

```bash
git clone --depth=1 https://github.com/OWASP/NodeGoat.git /tmp/NodeGoat
cd /tmp/NodeGoat && docker compose up -d

# Wait ~15s for MongoDB to initialise, then:
python3 /path/to/jspect.py \
    --dir /tmp/NodeGoat \
    -u http://localhost:4000
```

### Starting Juice Shop with Docker

```bash
docker run -d --name juiceshop -p 3000:3000 bkimminich/juice-shop

python3 /path/to/jspect.py -u http://localhost:3000
```

---

## Output Files

All files are written to the output directory alongside `report.html`:

| File | Contents |
|------|----------|
| `report.html` | Self-contained HTML report |
| `katana-out.txt` | Raw Katana crawl output (one URL per line) |
| `katana-target.txt` | Seed URL, used by Stage 2's homepage-fallback when crawl is empty |
| `js-urls.txt` | JS URLs selected for download |
| `js-clean/` | Downloaded (and beautified) JS corpus |
| `sources/` | Source-map recovered files (if any) |
| `url-map.json` | filename → original-URL mapping for everything in `js-clean/` |
| `endpoints.json` | JSluice + harvested endpoint extraction (JSONL) |
| `live-endpoints.json` | HTTP probe results (JSONL) |
| `live-endpoints-meta.json` | Cap/truncation metadata for Stage 5 |
| `http-calls.json` | fetch/axios/XHR/Express routes (JSONL) |
| `secrets.json` | JSluice secret candidates (JSONL) |
| `secrets-extended.json` | Extended regex secret matches with entropy gating |
| `semgrep.json` | Full Semgrep output (JSON) |
| `retire.json` | Full Retire.js output (JSON) |
| `trufflehog.json` | TruffleHog findings (JSONL) |
| `comments.json` | Developer comment findings (JSONL) |
| `dangling-js.json` | Nested JS references that 404'd (potential takeover) |
| `exposed-maps.json` | Reachable source maps + extracted source-path list |
| `wayback-maps.json` | Historical maps from Wayback Machine (Stage 5d) |
| `well-known.json` | Probed well-known files (robots, sitemap, .well-known/*, leaks, …) |
| `well-known-urls.txt` | URLs harvested from robots/sitemap chains |
| `well-known-trust.json` | Trusted domains from crossdomain/clientaccesspolicy |
| `well-known/` | Saved copies of every responding well-known file |
| `dorks.json` | Generated Google dork URLs (active-recon mode) |
| `recon-summary.json` | All files downloaded by active-recon (live + Wayback) |
| `recon-secrets.json` | Secret-pattern hits in recon downloads |
| `recon/` | Non-JS files downloaded by active-recon (configs, text, backups) |
| `swagger-endpoints.json` | Endpoints extracted from discovered Swagger/OpenAPI docs |
| `.semgrep-local.yaml` | Local Semgrep rules used for this run |

---

## Known Limitations

**Retire.js + Webpack bundles**
Webpack's tree-shaking removes version strings that Retire.js fingerprints against. Bundled apps (React, Angular, Vue) will often show 0 libraries detected even when vulnerable versions are in use. Use `--dir` with the `node_modules/` folder or check `package-lock.json` directly for accurate version data.

**Semgrep + Angular compiled templates**
Angular compiles `[innerHTML]="x"` into runtime calls like `h("innerHTML", x, sanitizer)` — not a direct property assignment. The local rule set includes `pattern-regex` rules that catch this compiled form, but some patterns may still be missed in heavily tree-shaken output.

**Authentication timeout**
Session cookies expire. For long runs (large targets, slow Semgrep), re-authenticate and restart if you start seeing 401/302 responses in the live endpoint results.

**NodeGoat / server-side apps in URL mode**
Katana can only crawl pages it can reach as the authenticated user. Server-side JS files (`routes/`, `data/`) are never served to the browser. Use `--dir` to analyse them.
