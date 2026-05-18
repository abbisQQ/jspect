# ─────────────────────────────────────────────────────────────────────────────
# Stage 1 — compile Go tools (katana, jsluice, sourcemapper)
# Only the compiled binaries are copied to the final image.
# ─────────────────────────────────────────────────────────────────────────────
FROM golang:1.25-bookworm AS go-builder

RUN go install github.com/projectdiscovery/katana/cmd/katana@latest    \
 && go install github.com/BishopFox/jsluice/cmd/jsluice@latest         \
 && go install github.com/denandz/sourcemapper@latest

# ─────────────────────────────────────────────────────────────────────────────
# Stage 2 — runtime image
# Base: python:3.11-slim-bookworm (Debian 12, small, reproducible)
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.11-slim-bookworm

LABEL org.opencontainers.image.title="jspect"
LABEL org.opencontainers.image.description="Automated JavaScript security analysis pipeline — Katana · JSluice · Semgrep · TruffleHog · Retire.js"
LABEL org.opencontainers.image.licenses="MIT"

# ── System packages ───────────────────────────────────────────────────────────
# Chromium and its shared-library dependencies for Katana headless crawl.
# curl + gnupg are needed to add the NodeSource repo for Node 20.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg \
        chromium \
        fonts-liberation \
        libatk-bridge2.0-0 libatk1.0-0 libcups2 libdbus-1-3 \
        libdrm2 libgbm1 libgtk-3-0 libnss3 libxss1 libxtst6 \
    && rm -rf /var/lib/apt/lists/*

# ── Node.js 20 LTS ───────────────────────────────────────────────────────────
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
 && apt-get install -y --no-install-recommends nodejs \
 && rm -rf /var/lib/apt/lists/*

# ── Node.js security tools ────────────────────────────────────────────────────
RUN npm install -g --quiet retire

# ── TruffleHog binary (arch-aware installer) ──────────────────────────────────
RUN curl -sSfL \
    https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
    | sh -s -- -b /usr/local/bin

# ── Go binaries (from stage 1) ────────────────────────────────────────────────
COPY --from=go-builder /go/bin/katana       /usr/local/bin/
COPY --from=go-builder /go/bin/jsluice      /usr/local/bin/
COPY --from=go-builder /go/bin/sourcemapper /usr/local/bin/

# ── Python tools ──────────────────────────────────────────────────────────────
RUN pip install --no-cache-dir semgrep jsbeautifier

# ── Environment ───────────────────────────────────────────────────────────────
# Point go-rod (Katana's browser engine) to the system Chromium.
ENV ROD_BROWSER_BIN=/usr/bin/chromium
# Disable Semgrep telemetry.
ENV SEMGREP_SEND_METRICS=off
# Tells the tool it is running in Docker so it adds --no-sandbox to Chrome.
ENV JSPECT_DOCKER=1

# ── Tool ──────────────────────────────────────────────────────────────────────
WORKDIR /jspect
COPY jspect.py .

# Reports are written to /output. Mount a host directory here:
#   docker run --rm -v $(pwd)/out:/output jspect -u https://target.com
# To analyse a local source tree, also mount it read-only:
#   docker run --rm -v $(pwd)/out:/output -v /path/to/src:/target:ro \
#              jspect --dir /target -u https://target.com
VOLUME ["/output"]
WORKDIR /output

ENTRYPOINT ["python3", "/jspect/jspect.py"]
