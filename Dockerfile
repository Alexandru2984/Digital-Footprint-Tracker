# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

# ─── Stage 1: Build ──────────────────────────────────────────────────────────
# Statically link the Swift runtime so the final image only needs system C libs.
FROM swift:6.3-jammy@sha256:a05aa080e573b1f7e10bd630ce9e1d7645abb08a32d1def73cb611ac708d2a8a AS builder
WORKDIR /build

# Resolve deps in a layer that only invalidates when the manifest changes.
# Source edits no longer pay the dependency-resolution cost on every rebuild.
COPY Package.swift Package.resolved ./
RUN --mount=type=cache,id=swift-vapor-spm-6.2,target=/build/.build,sharing=locked \
    swift package resolve

# Compile the release binary.
COPY Sources Sources
# SwiftPM validates every declared target even when only `Run` is built. Keep
# the test target path present in the builder; it is not copied into runtime.
COPY Tests Tests
RUN --mount=type=cache,id=swift-vapor-spm-6.2,target=/build/.build,sharing=locked \
    swift build -c release --static-swift-stdlib --product Run \
    && mkdir -p /staging \
    && cp .build/release/Run /staging/Run \
    && mkdir -p /staging/Sources/App/Plugins \
    && cp Sources/App/Plugins/sherlock_data.json /staging/Sources/App/Plugins/

# Optional verification target for local/CI use:
#   docker build --target test .
# It is intentionally not a dependency of the production runtime stage.
FROM builder AS test
RUN --mount=type=cache,id=swift-vapor-spm-6.2,target=/build/.build,sharing=locked \
    swift test

# ─── Stage 2: Runtime ────────────────────────────────────────────────────────
# Ubuntu (no Swift toolchain) — the binary is statically linked so we only
# need the system C libraries it dynamically depends on.
FROM ubuntu:26.04@sha256:2260313b31c8c011cd2eebe728008efac1b3982be73eb71348ea2648d2c0e09b AS runtime

# Runtime dependencies:
#   libatomic1 libcurl4 libxml2 — required by the Vapor binary
#   ca-certificates             — outbound TLS (HIBP, Shodan, VT, ip-api, …)
#   curl                        — used by EmailService for SMTPS (M-16)
#   python3 + venv              — isolated, hash-locked report/holehe runtime
#   tzdata                      — for Date/timezone parsing in audit logs
COPY requirements-runtime.txt /tmp/requirements-runtime.txt
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libatomic1 libcurl4 libxml2 ca-certificates tzdata \
        curl python3 python3-venv \
    && python3 -m venv /opt/python-runtime \
    && /opt/python-runtime/bin/pip install \
        --no-cache-dir --require-hashes \
        --requirement /tmp/requirements-runtime.txt \
    && rm -rf /var/lib/apt/lists/* /root/.cache \
    && rm -f /tmp/requirements-runtime.txt

# Non-root user with a non-default numeric identity. Avoiding UID/GID 1000
# prevents an accidental writable bind mount from mapping directly to the
# interactive owner of a typical Docker host.
RUN groupadd --gid 10001 app \
    && useradd --gid app --uid 10001 --home /app --shell /usr/sbin/nologin app

WORKDIR /app

COPY --from=builder --chown=app:app /staging /app
# Copy only the two runtime data files. Deployment, backup and maintenance
# scripts are host-side capabilities and must never be present in the image.
COPY --chown=app:app scripts/generate_report.py scripts/generate_report.py
COPY --chown=app:app frontend/openapi.yaml frontend/openapi.yaml

USER app

ENV HOLEHE_PATH=/opt/python-runtime/bin/holehe \
    REPORT_PYTHON_PATH=/opt/python-runtime/bin/python3 \
    CURL_PATH=/usr/bin/curl

EXPOSE 8080

# /health is a constant-cost process liveness probe. Dependency readiness is
# available separately at loopback-only /ready, so a DB outage does not create
# an application restart loop.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/health || exit 1

ENTRYPOINT ["./Run"]
CMD ["serve", "--env", "production", "--hostname", "0.0.0.0", "--port", "8080"]
