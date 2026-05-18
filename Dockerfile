# syntax=docker/dockerfile:1.7

# ─── Stage 1: Build ──────────────────────────────────────────────────────────
# Statically link the Swift runtime so the final image only needs system C libs.
FROM swift:6.0-jammy AS builder
WORKDIR /build

# Resolve deps in a layer that only invalidates when the manifest changes.
# Source edits no longer pay the dependency-resolution cost on every rebuild.
COPY Package.swift Package.resolved ./
RUN swift package resolve

# Compile the release binary.
COPY Sources Sources
RUN swift build -c release --static-swift-stdlib --product Run

# Stage the runtime artefacts in one place so the COPY in stage 2 stays clean.
RUN mkdir -p /staging \
    && cp .build/release/Run /staging/Run \
    && mkdir -p /staging/Sources/App/Plugins \
    && cp Sources/App/Plugins/sherlock_data.json /staging/Sources/App/Plugins/

# ─── Stage 2: Runtime ────────────────────────────────────────────────────────
# Ubuntu (no Swift toolchain) — the binary is statically linked so we only
# need the system C libraries it dynamically depends on.
FROM ubuntu:22.04 AS runtime

# Runtime dependencies:
#   libatomic1 libcurl4 libxml2 — required by the Vapor binary
#   ca-certificates             — outbound TLS (HIBP, Shodan, VT, ip-api, …)
#   curl                        — used by EmailService for SMTPS (M-16)
#   python3 + pip               — fpdf2 (PDF reports) + holehe (BulkEmail plugin)
#   tzdata                      — for Date/timezone parsing in audit logs
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libatomic1 libcurl4 libxml2 ca-certificates tzdata \
        curl python3 python3-pip \
    && pip3 install --no-cache-dir --break-system-packages fpdf2 holehe \
    && apt-get purge -y python3-pip \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* /root/.cache

# Resolve where pip dropped holehe so the BulkEmail plugin can find it without
# the operator having to set HOLEHE_PATH manually.
RUN ln -sf "$(command -v holehe)" /usr/local/bin/holehe || true

# Non-root user. UID/GID 1000 lines up with typical host users so any
# bind-mounted volume doesn't end up owned by root.
RUN groupadd --system --gid 1000 app \
    && useradd  --system --gid app --uid 1000 --home /app --shell /usr/sbin/nologin app

WORKDIR /app

COPY --from=builder --chown=app:app /staging /app
COPY --chown=app:app scripts scripts
COPY --chown=app:app frontend frontend

USER app

ENV HOLEHE_PATH=/usr/local/bin/holehe \
    CURL_PATH=/usr/bin/curl

EXPOSE 8080

# /health returns 200 OK once the DB is reachable. Orchestrators use this to
# gate traffic + restart the container on prolonged failure.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/health || exit 1

ENTRYPOINT ["./Run"]
CMD ["serve", "--env", "production", "--hostname", "0.0.0.0", "--port", "8080"]
