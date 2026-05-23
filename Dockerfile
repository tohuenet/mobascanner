# syntax=docker/dockerfile:1.7
#
# moba-scanner — single image, all batteries included.
#
# Stage A builds the Next.js app into a self-contained standalone bundle.
# Stage B is the runtime: same Node base + every scanner CLI baked into PATH,
# so `docker compose up --build` is the only step needed to use the platform.
#
# Bumping a tool: change its *_VERSION ARG, rebuild. Pins keep builds reproducible.

# ─── Stage 1: build the Next app ────────────────────────────────────────────────
FROM node:20-bookworm-slim AS builder

WORKDIR /app

# Project's lockfile is pnpm. pnpm 10+ is needed because pnpm-workspace.yaml
# uses the `allowBuilds` config which earlier versions treat as an invalid
# workspace declaration.
RUN corepack enable && corepack prepare pnpm@10 --activate

# Cache deps independently of source changes.
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile

# Build the standalone server bundle (driven by output:"standalone" in next.config.ts).
COPY . .
RUN pnpm run build


# ─── Stage 2: runtime — Next + every scanner CLI on PATH ────────────────────────
FROM node:20-bookworm-slim AS runtime

# Use bash for every RUN so `set -o pipefail` works (Debian's default /bin/sh is
# dash, which lacks pipefail — that previously hid failed curl-into-tar pipes).
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Pinned tool versions. Bump deliberately.
ARG NUCLEI_VERSION=3.3.10
ARG FFUF_VERSION=2.1.0
ARG SUBFINDER_VERSION=2.6.6
ARG HTTPX_VERSION=1.6.9
ARG KATANA_VERSION=1.1.2
ARG NAABU_VERSION=2.3.4
ARG INTERACTSH_VERSION=1.2.4
ARG GITLEAKS_VERSION=8.21.2
ARG TRIVY_VERSION=0.55.2
ARG OSV_VERSION=1.9.2
ARG TRUFFLEHOG_VERSION=3.86.1
ARG DOCKLE_VERSION=0.4.14
ARG HADOLINT_VERSION=2.12.0
ARG KUBE_BENCH_VERSION=0.10.7
ARG PLAYWRIGHT_VERSION=1.59.1

# Provided by BuildKit (amd64 | arm64). Used to pick the right release tarballs.
ARG TARGETARCH

ENV PIPX_HOME=/opt/pipx \
    PIPX_BIN_DIR=/usr/local/bin \
    NODE_ENV=production \
    PORT=3000 \
    HOSTNAME=0.0.0.0

# ── system packages: apt-shipped scanners + runtimes for the python/ruby tools ──
# nikto isn't in Debian bookworm's default repos any more — installed from source below.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl wget git unzip jq openssl bash bsdmainutils gnupg procps \
      python3 python3-pip python3-dev pipx \
      libffi-dev libssl-dev \
      ruby ruby-dev build-essential \
      perl libnet-ssleay-perl libjson-perl libxml-writer-perl libxml-simple-perl \
      nmap masscan \
 && rm -rf /var/lib/apt/lists/*

# ── nikto from upstream (Perl script — runs from a checkout) ──
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
 && chmod +x /opt/nikto/program/nikto.pl \
 && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto

# ── python tools via pipx (sidesteps PEP 668 on Debian 12) ──
RUN set -eux; \
    pipx install semgrep; \
    pipx install sqlmap; \
    pipx install wapiti3; \
    pipx install bandit; \
    pipx install checkov; \
    pipx install detect-secrets; \
    pipx install kube-hunter; \
    pipx install prowler; \
    pipx install scoutsuite

# ── ruby gem ──
RUN gem install --no-document brakeman

# ── npm globals (snyk needs `snyk auth` at runtime; cdxgen for SBOMs) ──
RUN npm install -g snyk @cyclonedx/cdxgen

# ── prebuilt binaries from GitHub releases, arch-aware ──────────────────────────
# Keeps the final image free of the Go toolchain (~300MB savings). Each helper
# uses sequential statements (no `&&` short-circuit) so a failed download or
# extract trips set -e and fails the build loudly instead of leaving the binary
# missing from the image.
RUN set -euxo pipefail; \
    case "$TARGETARCH" in \
      amd64) PD_ARCH=amd64; GL_ARCH=x64; TRIVY_ARCH=64bit; TH_ARCH=amd64; DOCKLE_ARCH=64bit; HADO_ARCH=x86_64; KB_ARCH=amd64; OSV_ARCH=amd64 ;; \
      arm64) PD_ARCH=arm64; GL_ARCH=arm64; TRIVY_ARCH=ARM64; TH_ARCH=arm64; DOCKLE_ARCH=ARM64; HADO_ARCH=arm64; KB_ARCH=arm64; OSV_ARCH=arm64 ;; \
      *) echo "unsupported arch: $TARGETARCH"; exit 1 ;; \
    esac; \
    fetch_zip() { local u="$1" f="$2"; echo "→ zip $f"; curl -fsSL -o /tmp/dl.zip "$u"; unzip -q -o /tmp/dl.zip "$f" -d /usr/local/bin; rm /tmp/dl.zip; }; \
    fetch_tar() { local u="$1" f="$2"; echo "→ tar $f"; curl -fsSL -o /tmp/dl.tgz "$u"; tar -xzf /tmp/dl.tgz -C /usr/local/bin "$f"; rm /tmp/dl.tgz; }; \
    fetch_bin() { local u="$1" d="$2"; echo "→ bin $d"; curl -fsSL -o "$d" "$u"; chmod +x "$d"; }; \
    # ProjectDiscovery suite — zip with <name>_<ver>_linux_<arch>.zip
    for entry in \
        "nuclei:${NUCLEI_VERSION}:projectdiscovery/nuclei" \
        "subfinder:${SUBFINDER_VERSION}:projectdiscovery/subfinder" \
        "httpx:${HTTPX_VERSION}:projectdiscovery/httpx" \
        "katana:${KATANA_VERSION}:projectdiscovery/katana" \
        "naabu:${NAABU_VERSION}:projectdiscovery/naabu" \
        "interactsh-client:${INTERACTSH_VERSION}:projectdiscovery/interactsh" ; do \
      name="${entry%%:*}"; rest="${entry#*:}"; ver="${rest%%:*}"; repo="${rest#*:}"; \
      fetch_zip "https://github.com/${repo}/releases/download/v${ver}/${name}_${ver}_linux_${PD_ARCH}.zip" "${name}"; \
    done; \
    # ffuf — separate project, ships as tar.gz.
    fetch_tar "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_${PD_ARCH}.tar.gz" "ffuf"; \
    # gitleaks
    fetch_tar "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GL_ARCH}.tar.gz" "gitleaks"; \
    # trivy installed below from Aqua's apt repo — its GitHub release filenames
    # have churned across minor versions; the apt repo is the documented method.
    # osv-scanner — `latest` redirect dodges the version-in-filename naming churn between v1.x and v2.x.
    fetch_bin "https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_${OSV_ARCH}" "/usr/local/bin/osv-scanner"; \
    # trufflehog
    fetch_tar "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_${TH_ARCH}.tar.gz" "trufflehog"; \
    # dockle
    fetch_tar "https://github.com/goodwithtech/dockle/releases/download/v${DOCKLE_VERSION}/dockle_${DOCKLE_VERSION}_Linux-${DOCKLE_ARCH}.tar.gz" "dockle"; \
    # hadolint (bare binary)
    fetch_bin "https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/hadolint-Linux-${HADO_ARCH}" "/usr/local/bin/hadolint"; \
    # kube-bench
    fetch_tar "https://github.com/aquasecurity/kube-bench/releases/download/v${KUBE_BENCH_VERSION}/kube-bench_${KUBE_BENCH_VERSION}_linux_${KB_ARCH}.tar.gz" "kube-bench"

# ── trivy via Aqua's official apt repo (stable URL, signed packages) ──
RUN install -m 0755 -d /etc/apt/keyrings \
 && curl -fsSL https://aquasecurity.github.io/trivy-repo/deb/public.key \
      | gpg --dearmor -o /etc/apt/keyrings/trivy.gpg \
 && echo "deb [signed-by=/etc/apt/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
      > /etc/apt/sources.list.d/trivy.list \
 && apt-get update && apt-get install -y --no-install-recommends trivy \
 && rm -rf /var/lib/apt/lists/*

# ── testssl.sh (Bash script — relies on bash + openssl, already present) ──
RUN git clone --depth 1 --branch 3.2 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh \
 && ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh

# ── Playwright + Chromium (for web.dom-xss) ──────────────────────────────────────
# --with-deps installs the apt prerequisites Chromium needs. Browser cache lands
# in /root/.cache/ms-playwright, where playwright-core in the standalone bundle
# will find it without extra env vars (container runs as root).
RUN apt-get update \
 && npm install -g playwright@${PLAYWRIGHT_VERSION} \
 && playwright install --with-deps chromium \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

# ── ship the app ────────────────────────────────────────────────────────────────
WORKDIR /app

# Next standalone bundle: server.js + traced node_modules.
COPY --from=builder /app/.next/standalone ./
# Static assets aren't in the standalone bundle.
COPY --from=builder /app/.next/static ./.next/static
COPY --from=builder /app/public ./public

# Belt-and-suspenders: ensure playwright-core ends up at /app/node_modules in case
# the standalone tracer missed the indirect import in lib/scanners/web/dom-xss.ts.
COPY --from=builder /app/node_modules/playwright-core ./node_modules/playwright-core

# Persistence dir — lib/store.ts writes here (process.cwd()/data). Bind-mounted
# from the host via docker-compose so scan history survives container restarts.
RUN mkdir -p /app/data

EXPOSE 3000
CMD ["node", "server.js"]
