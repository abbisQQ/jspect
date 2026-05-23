# jspect

Automated JavaScript security analysis pipeline. Crawls a target, pulls every JS asset, runs the standard tool chain (Katana → JSluice → Semgrep → Retire.js → TruffleHog) plus a few extras (source-map blind-probe, Wayback, well-known files, AJAX spider), and produces a single self-contained HTML report.

---

## Three ways to run it

```bash
# 1. CLI — one command
jspect -u https://target.com

# 2. Terminal wizard — guided prompts
jspect -i

# 3. Web wizard — browser UI on localhost
jspect --serve
```

The web wizard also accepts a **raw Burp request** (paste from Burp's "Copy request" clipboard) and auto-extracts URL + cookies + auth headers.

---

## Install

### Docker (recommended — bundles every dependency)

```bash
git clone https://github.com/abbisQQ/jspect
cd jspect
docker build -t jspect .

# Then any of:
docker run --rm -v $(pwd)/out:/output jspect -u https://target.com
docker run --rm -it -v $(pwd)/out:/output jspect -i
docker run --rm -p 8765:8765 -v $(pwd)/out:/output jspect --serve --bind 0.0.0.0
```

### Native (macOS / Linux)

```bash
pip install -r requirements.txt
# External binaries (one-time):
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/BishopFox/jsluice/cmd/jsluice@latest
go install github.com/denandz/sourcemapper@latest
npm install -g retire
brew install trufflehog                                  # or: see install.sh on trufflehog repo
playwright install chromium                              # only for --ajax-spider
```

Run with `python3 jspect.py -u https://target.com`.

---

## Profiles

Pick the intensity. Most flags below are bundled into these:

| Profile | Threads | Cap | AJAX spider | Active recon | Wayback | When |
|---------|--------:|----:|:-----------:|:------------:|:-------:|------|
| `fast` | 10 | 200 | off | off | off | Triage — ~30s |
| `default` ★ | 10 | 500 | **on** | off | on | Most engagements |
| `full` | 10 | ∞ | on | on | on | Maximum coverage (~10-30 min) |
| `gentle` | 1 | 200 | off | off | off | Polite to small / fragile targets |

```bash
jspect -u https://target.com --profile gentle
```

---

## Common flags

```
-u URL                 Target URL
--dir PATH             Local source directory (skips crawl)
-H "Cookie: ..."       Auth header (repeatable)
--from-burp FILE       Read raw HTTP request from file (or '-' for stdin)
-o DIR                 Output directory (default: auto-timestamped)
--profile MODE         fast / default / full / gentle
--proxy URL            Route everything through Burp / mitmproxy / Tor
-i                     Terminal wizard
--serve [--port N]     Web wizard (default port 8765)
--help-advanced        Show ~15 more advanced flags
```

### Authenticated scan (any of these works)

```bash
jspect -u https://app.example.com -H "Cookie: session=..." -H "Authorization: Bearer eyJ..."
jspect --from-burp /path/to/burp-request.txt
pbpaste | jspect --from-burp -                   # macOS — pipe a Burp clipboard
```

### Pipe everything through Burp

```bash
jspect -u https://target.com --proxy http://127.0.0.1:8080 --proxy-insecure
```

Every request — Katana crawl, JS downloads, live-validation probes, well-known, Wayback, AJAX spider, blind source-map probes — appears in Burp's sitemap.

---

## What the report shows

The HTML report opens with a **Critical Findings** TL;DR (CVEs, exposed maps, ERROR-severity SAST, leaks, dangling JS, etc.) and links straight to each row. Below that:

| Section | Content |
|---------|---------|
| Endpoints | Every URL the JS code calls (jsluice AST extraction) |
| AJAX Spider | URLs only discovered after JS hydration / clicks (when `--ajax-spider`) |
| Live Endpoints | HTTP probe results — status, type, size, title |
| HTTP Calls | `fetch` / `axios` / `XHR` / Express routes from source |
| Source Maps | Exposed `.map` files (extracts the original source tree) |
| Libraries | Retire.js findings — vulnerable lib versions + CVEs |
| Semgrep | DOM-XSS / `eval` / open-redirect / cookie misconfig |
| Secrets | JWT / AWS / API key patterns + TruffleHog candidates |
| Well-known | `robots.txt` / `sitemap.xml` / `.well-known/*` / `.git/*` / `.env*` / etc. |
| Comments | TODO / FIXME / credential mentions in JS source |

Empty sections collapse to a single "no findings" line — the report stays scannable even on clean targets.

---

## The web wizard

`jspect --serve` boots a localhost-only HTTP server (default `127.0.0.1:8765`). Three pages:

| URL | Page |
|-----|------|
| `/` | Form — start a new scan (URL tab + Burp-request tab + advanced options) |
| `/jobs/<id>` | Live progress — stage-by-stage SSE stream + Stop / Browse / Report buttons |
| `/scans` | Past-scan history — every scan dir on disk, regardless of server lifetime |

Submits a scan as a subprocess; **Stop scan** sends SIGTERM (3s grace) → SIGKILL. Partial output is preserved.

To expose externally (use a VPN — there's no auth):

```bash
jspect --serve --bind 0.0.0.0 --port 8765
```

---

## Pipeline stages (FYI)

```
1.  Katana crawl                 (URL mode)
1b. AJAX spider                  (Playwright, opt-in via profile)
2.  JS download                  + HTML <script src> fallback
2b. Multi-level discovery        chases nested JS imports
2c. JS beautification
3.  Source-map recovery          (extract bundled source)
4.  JSluice                      AST-based URL / secret extraction
4b. Active recon                 Google dorks + broad Wayback CDX
4c. Well-known probe             43 paths, leak content-shape validator
5.  Live endpoint validation     HTTP probe + status classification
5b. Static metadata              source-maps, JSON, comments
5c. HTTP-call + extended secrets regex sweep on JS corpus
5d. Wayback historical maps      CDX API for *.js.map
6.  Semgrep SAST                 ~80 local rules
7.  Retire.js                    known-CVE library fingerprinting
8.  TruffleHog                   high-entropy secret detection
9.  HTML report                  collapsible, single-file, dark theme
```

Each stage is graceful — missing tools / failed crawls / empty corpora don't break downstream stages.

---

## Acknowledgments

jspect orchestrates a pipeline of excellent open-source tools — full credit to their authors.

**Required binaries**
- [Katana](https://github.com/projectdiscovery/katana) (ProjectDiscovery) — web crawler
- [JSluice](https://github.com/BishopFox/jsluice) (BishopFox) — AST-based URL + secret extraction from JavaScript
- [Semgrep](https://github.com/semgrep/semgrep) (Semgrep, Inc.) — static analysis engine; rules at [semgrep.dev/explore](https://semgrep.dev/explore)
- [Retire.js](https://github.com/RetireJS/retire.js) (Erlend Oftedal) — known-vulnerable JavaScript library detection
- [TruffleHog](https://github.com/trufflesecurity/trufflehog) (Truffle Security) — high-entropy secret detection

**Optional**
- [Playwright](https://github.com/microsoft/playwright) (Microsoft) — headless Chromium for the `--ajax-spider` stage
- [sourcemapper](https://github.com/denandz/sourcemapper) (denandz) — source-map unpacking
- [unwebpack-sourcemap](https://github.com/rarecoil/unwebpack-sourcemap) (rarecoil) — fallback source-map extractor
- [jsbeautifier](https://github.com/beautifier/js-beautify) (Einar Lielmanis et al.) — JS beautification
- [MapperPlus](https://github.com/Zierax/MapperPlus) (Zierax) — alternative source-map helper, auto-detected if cloned into `./mapperplus/`

**Data sources**
- [Wayback Machine CDX API](https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server) (Internet Archive) — historical `.js.map` URLs (Stage 5d)
- [Google Custom Search JSON API](https://developers.google.com/custom-search/v1/overview) — optional auto-fetch of `--active-recon` dorks when `GOOGLE_API_KEY` + `GOOGLE_CSE_ID` env vars are set

Inspired by the broader JS-recon community — particularly the writeups collected in [insecrez/Bug-bounty-Writeups](https://github.com/insecrez/Bug-bounty-Writeups) and [devanshbatham/Awesome-Bugbounty-Writeups](https://github.com/devanshbatham/Awesome-Bugbounty-Writeups), which informed several of the bundled Semgrep rules.

---

## License

[MIT](LICENSE) — free to use, modify, distribute, including commercially.

Only scan systems you own or have **explicit written authorization** to test. Automated tooling can trigger WAFs, exhaust rate limits, fill audit logs, and submit forms — review the `--ajax-fill-forms` and `--verify-secrets` sections before pointing it at production third-party services.
