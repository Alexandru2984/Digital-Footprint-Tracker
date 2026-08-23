#!/usr/bin/python3
"""Loopback-only, one-job-at-a-time adapter for VoidAccess CLI 2.0.3.

This service deliberately returns only normalized entities and relationships.
It never returns page bodies, snippets, scraped URLs, local paths or the query.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

MAX_REQUEST_BYTES = 4096
MAX_RESULT_BYTES = 8 * 1024 * 1024
MAX_FINDINGS = 250
MAX_RELATIONSHIPS = 500
MAX_CLOCK_SKEW_SECONDS = 60
MAX_JOB_SECONDS = int(os.environ.get("VOIDACCESS_JOB_TIMEOUT_SECONDS", "540"))
TARGET_RE = re.compile(r"^[A-Za-z0-9@._+\-]{1,255}$")
DATE_RE = re.compile(r"^\d{4}(?:-\d{2}(?:-\d{2})?)?$")
SOURCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+ \-]{0,79}$")
RELATIONSHIP_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ \-]{0,63}$")
ALLOWED_KINDS = {"email", "domain", "phone", "username"}
ALLOWED_DEPTH = {"shallow"}
NORMALIZED_TYPES = {
    "email",
    "domain",
    "onion_service",
    "ip",
    "phone",
    "username",
    "messaging_handle",
    "crypto_wallet",
    "file_hash",
    "vulnerability",
    "malware",
    "threat_actor",
    "organization",
    "date",
    "technique",
    "credential_exposure",
    "network_indicator",
}

TYPE_MAP = {
    "EMAIL": "email",
    "EMAIL_ADDRESS": "email",
    "DOMAIN": "domain",
    "ENS_DOMAIN": "domain",
    "IP_ADDRESS": "ip",
    "IPV6_ADDRESS": "ip",
    "PHONE": "phone",
    "PHONE_NUMBER": "phone",
    "THREAT_ACTOR_HANDLE": "threat_actor",
    "RANSOMWARE_GROUP": "threat_actor",
    "MALWARE": "malware",
    "MALWARE_FAMILY": "malware",
    "ORGANIZATION_NAME": "organization",
    "DATE": "date",
    "CVE": "vulnerability",
    "CVE_NUMBER": "vulnerability",
    "EXPLOIT_DB_ID": "vulnerability",
    "MITRE_TACTIC": "technique",
    "MITRE_TECHNIQUE": "technique",
    "YARA_RULE": "technique",
    "NUCLEI_TEMPLATE": "technique",
    "MAC_ADDRESS": "network_indicator",
    "IPFS_CID": "file_hash",
    "FILE_HASH_MD5": "file_hash",
    "FILE_HASH_SHA1": "file_hash",
    "FILE_HASH_SHA256": "file_hash",
    "TELEGRAM_HANDLE": "messaging_handle",
    "DISCORD_HANDLE": "messaging_handle",
    "XMPP_JID": "messaging_handle",
    "TOX_ID": "messaging_handle",
    "MATRIX_HANDLE": "messaging_handle",
    "WIRE_HANDLE": "messaging_handle",
    "ICQ_NUMBER": "messaging_handle",
    "WICKR_ID": "messaging_handle",
}

WALLET_TYPES = {
    "CRYPTO_WALLET",
    "BITCOIN_ADDRESS",
    "BTC_ADDRESS",
    "ETHEREUM_ADDRESS",
    "ETH_ADDRESS",
    "MONERO_ADDRESS",
    "XMR_ADDRESS",
    "LITECOIN_ADDRESS",
    "ZCASH_ADDRESS",
    "DOGECOIN_ADDRESS",
    "XRP_ADDRESS",
    "SOLANA_ADDRESS",
    "TRON_ADDRESS",
    "BITCOIN_CASH_ADDRESS",
    "DASH_ADDRESS",
}

# VoidAccess extracts live tokens and credential material as first-class
# entities. Those values must never cross this adapter boundary. Preserve the
# defensive signal while replacing the secret with a non-reversible label.
SENSITIVE_TYPE_MARKERS = (
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PRIVATE_KEY",
    "_KEY",
    "API_KEY",
    "ACCESS_KEY",
    "SEED_PHRASE",
    "STEALER_LOG",
    "COMBO_LIST",
    "SESSION_ID",
    "CREDENTIAL",
)

_job_lock = threading.Lock()
_active_lock = threading.Lock()
_active_job_id: str | None = None
_active_process: subprocess.Popen | None = None
_replay_lock = threading.Lock()
_seen_signatures: dict[str, float] = {}
_shared_secret = b""


def _bounded_text(value: object, maximum: int) -> str | None:
    if not isinstance(value, str):
        return None
    clean = " ".join(value.split()).strip()
    if not clean or len(clean.encode("utf-8")) > maximum:
        return None
    if any(ord(char) < 32 or ord(char) == 127 for char in clean):
        return None
    return clean


def _valid_date(value: object) -> str | None:
    clean = _bounded_text(value, 10) if value is not None else None
    return clean if clean and DATE_RE.fullmatch(clean) else None


def _confidence(value: object) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    return min(1.0, max(0.0, number))


def _source_name(entity: dict) -> str:
    source = _bounded_text(entity.get("corroborating_sources"), 80)
    if source:
        candidate = source.split(",", 1)[0].strip()
        if "://" in candidate:
            candidate = urlsplit(candidate).hostname or ""
        if SOURCE_RE.fullmatch(candidate):
            return candidate
    source_url = _bounded_text(entity.get("source_url"), 2048)
    if source_url:
        host = urlsplit(source_url).hostname
        if host:
            return host[:80]
    return "voidaccess"


def _normalized_entity(entity_type: str, value: str) -> tuple[str, str] | None:
    upper_type = entity_type.strip().upper()
    if any(marker in upper_type for marker in SENSITIVE_TYPE_MARKERS):
        label = upper_type.lower().replace("_", " ")[:48]
        return "credential_exposure", f"{label} detected"

    if upper_type in {"ONION_URL", "PASTE_URL", "URL"}:
        parsed = urlsplit(value if "://" in value else f"http://{value}")
        host = (parsed.hostname or "").lower().rstrip(".")
        if not host or len(host.encode("utf-8")) > 253:
            return None
        return ("onion_service" if host.endswith(".onion") else "domain", host)

    if upper_type in WALLET_TYPES:
        return "crypto_wallet", value
    normalized_type = TYPE_MAP.get(upper_type)
    if normalized_type not in NORMALIZED_TYPES:
        return None
    return normalized_type, value


def normalize(raw: dict) -> dict:
    entities = raw.get("entities") if isinstance(raw.get("entities"), list) else []
    findings: list[dict] = []
    id_to_value: dict[str, str] = {}
    seen: set[tuple[str, str, str]] = set()

    for entity in entities[:2000]:
        if not isinstance(entity, dict):
            continue
        entity_type = _bounded_text(entity.get("entity_type"), 64)
        value = _bounded_text(entity.get("value"), 512)
        source = _source_name(entity)
        if not entity_type or not value or not source:
            continue
        normalized = _normalized_entity(entity_type, value)
        if normalized is None:
            continue
        normalized_type, normalized_value = normalized
        key = (normalized_type, normalized_value.casefold(), source.casefold())
        if key in seen:
            continue
        seen.add(key)
        finding = {
            "type": normalized_type,
            "value": normalized_value,
            "source": source,
            "confidence": _confidence(entity.get("confidence")),
            "firstSeen": _valid_date(entity.get("first_seen")),
            "lastSeen": _valid_date(entity.get("last_seen")),
        }
        findings.append(finding)
        entity_id = _bounded_text(entity.get("id"), 80)
        if entity_id:
            id_to_value[entity_id] = normalized_value
        if len(findings) >= MAX_FINDINGS:
            break

    relationships: list[dict] = []
    relationship_rows = raw.get("relationships")
    if isinstance(relationship_rows, list):
        for relationship in relationship_rows[:2000]:
            if not isinstance(relationship, dict):
                continue
            source = id_to_value.get(str(relationship.get("entity_a_id", "")))
            target = id_to_value.get(str(relationship.get("entity_b_id", "")))
            kind = _bounded_text(relationship.get("relationship_type"), 64)
            if not source or not target or not kind or not RELATIONSHIP_RE.fullmatch(kind):
                continue
            relationships.append({
                "source": source,
                "target": target,
                "type": kind,
                "confidence": _confidence(relationship.get("confidence")),
            })
            if len(relationships) >= MAX_RELATIONSHIPS:
                break

    sources = sorted({finding["source"] for finding in findings})[:64]
    return {
        "schemaVersion": 1,
        "status": "completed",
        "findings": findings,
        "relationships": relationships,
        "sources": sources,
    }


def _load_shared_secret() -> bytes:
    inline = os.environ.get("VOIDACCESS_SHARED_SECRET", "")
    file_name = os.environ.get("VOIDACCESS_SHARED_SECRET_FILE", "")
    if inline and file_name:
        raise RuntimeError("multiple_shared_secret_sources")
    if file_name:
        path = Path(file_name)
        if not path.is_absolute() or path == Path("/") or not path.is_file():
            raise RuntimeError("invalid_shared_secret_file")
        if path.stat().st_size > 512:
            raise RuntimeError("invalid_shared_secret_file")
        try:
            secret = path.read_bytes().rstrip(b"\r\n")
        except OSError as error:
            raise RuntimeError("invalid_shared_secret_file") from error
    else:
        secret = inline.encode()
    if not 32 <= len(secret) <= 512 or any(byte < 33 or byte > 126 for byte in secret):
        raise RuntimeError("invalid_shared_secret")
    return secret


def _validate_runtime(check_tor: bool) -> None:
    executable = Path(os.environ.get(
        "VOIDACCESS_EXECUTABLE", "/opt/voidaccess/current/venv/bin/voidaccess"
    ))
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise RuntimeError("worker_not_installed")

    runtime_python = os.environ.get("VOIDACCESS_PYTHON")
    python_path = Path(runtime_python) if runtime_python else executable.parent / "python"
    if not python_path.is_file() or not os.access(python_path, os.X_OK):
        raise RuntimeError("worker_python_unavailable")
    result = subprocess.run(
        [str(python_path), "-c", "import spacy; spacy.load('en_core_web_sm')"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
        check=False,
        env={
            "HOME": os.environ.get("HOME", "/var/lib/swift-voidaccess"),
            "PATH": "/usr/bin:/bin",
            "PYTHONNOUSERSITE": "1",
        },
    )
    if result.returncode != 0:
        raise RuntimeError("spacy_model_unavailable")

    if check_tor:
        tor_host = os.environ.get("TOR_PROXY_HOST", "127.0.0.1")
        tor_port = int(os.environ.get("TOR_PROXY_PORT", "9050"))
        if tor_host not in {"127.0.0.1", "::1"} or not 1 <= tor_port <= 65535:
            raise RuntimeError("invalid_tor_endpoint")
        try:
            with socket.create_connection((tor_host, tor_port), timeout=2):
                pass
        except OSError as error:
            raise RuntimeError("tor_unavailable") from error


def verify_request(
    headers, method: str, path: str, body: bytes, *, reject_replay: bool = True
) -> bool:
    secret = _shared_secret
    timestamp = headers.get("X-DFT-Timestamp", "")
    signature = headers.get("X-DFT-Signature", "")
    if len(secret) < 32 or not timestamp.isdigit() or len(signature) != 64:
        return False
    if abs(time.time() - int(timestamp)) > MAX_CLOCK_SKEW_SECONDS:
        return False
    message = timestamp.encode() + b"\n" + method.upper().encode() + b"\n" + path.encode() + b"\n" + body
    expected = hmac.new(secret, message, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return False
    if not reject_replay:
        return True
    now = time.time()
    with _replay_lock:
        stale = [item for item, seen_at in _seen_signatures.items() if now - seen_at > 120]
        for item in stale:
            _seen_signatures.pop(item, None)
        if signature in _seen_signatures:
            return False
        if len(_seen_signatures) >= 1024:
            return False
        _seen_signatures[signature] = now
    return True


def run_voidaccess(payload: dict) -> dict:
    global _active_job_id, _active_process
    target = payload.get("target")
    job_id = payload.get("jobID")
    kind = payload.get("targetKind")
    depth = payload.get("depth")
    if (
        not isinstance(job_id, str)
        or str(uuid.UUID(job_id)) != job_id.lower()
        or not isinstance(target, str)
        or not TARGET_RE.fullmatch(target)
        or kind not in ALLOWED_KINDS
        or depth not in ALLOWED_DEPTH
        or payload.get("useTor") is not True
        or payload.get("useLLM") is not False
    ):
        raise ValueError("invalid_request")

    executable = os.environ.get(
        "VOIDACCESS_EXECUTABLE", "/opt/voidaccess/current/venv/bin/voidaccess"
    )
    if not Path(executable).is_file() or not os.access(executable, os.X_OK):
        raise RuntimeError("worker_not_installed")

    with tempfile.TemporaryDirectory(prefix="voidaccess-job-") as temp:
        job_home = Path(temp)
        output_dir = job_home / "result"
        output_dir.mkdir(mode=0o700)
        environment = {
            "HOME": str(job_home),
            "TMPDIR": str(job_home),
            "PATH": "/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PYTHONUNBUFFERED": "1",
            "VOIDACCESS_NO_BANNER": "1",
            "VOIDACCESS_PACE": "normal",
            "TOR_PROXY_HOST": "127.0.0.1",
            "TOR_PROXY_PORT": os.environ.get("TOR_PROXY_PORT", "9050"),
            "PLAYWRIGHT_ENABLED": "false",
        }
        command = [
            executable,
            "--no-banner",
            "investigate",
            target,
            "--no-llm",
            "--depth",
            "shallow",
            "--format",
            "json",
            "--output",
            str(output_dir),
            "--quiet",
        ]
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=environment,
            start_new_session=True,
        )
        with _active_lock:
            _active_job_id = job_id.lower()
            _active_process = process
        try:
            try:
                exit_code = process.wait(timeout=MAX_JOB_SECONDS)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                raise TimeoutError("worker_timeout")
        finally:
            with _active_lock:
                if _active_process is process:
                    _active_job_id = None
                    _active_process = None
        if exit_code != 0:
            raise RuntimeError("worker_failed")

        outputs = list(output_dir.glob("*.json"))
        if len(outputs) != 1 or outputs[0].stat().st_size > MAX_RESULT_BYTES:
            raise RuntimeError("invalid_output")
        with outputs[0].open("rb") as stream:
            raw = json.load(stream)
        if not isinstance(raw, dict):
            raise RuntimeError("invalid_output")
        return normalize(raw)


class Handler(BaseHTTPRequestHandler):
    server_version = "DFT-VoidAccess-Worker/1"

    def log_message(self, _format: str, *_args) -> None:
        return

    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/health":
            self._json(404, {"error": "not_found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if length != 0 or not verify_request(
            self.headers, "GET", self.path, b"", reject_replay=False
        ):
            self._json(401, {"error": "unauthorized"})
            return
        self._json(200, {"status": "ok"})

    def do_POST(self) -> None:  # noqa: N802
        cancel_match = re.fullmatch(
            r"/v1/investigations/([0-9A-Fa-f-]{36})/cancel", self.path
        )
        if self.path != "/v1/investigations" and cancel_match is None:
            self._json(404, {"error": "not_found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if self.path == "/v1/investigations" and (length <= 0 or length > MAX_REQUEST_BYTES):
            self._json(413, {"error": "invalid_size"})
            return
        if cancel_match is not None and length != 0:
            self._json(413, {"error": "invalid_size"})
            return
        body = self.rfile.read(length)
        if not verify_request(self.headers, "POST", self.path, body):
            self._json(401, {"error": "unauthorized"})
            return
        if cancel_match is not None:
            try:
                requested_id = str(uuid.UUID(cancel_match.group(1)))
            except ValueError:
                self._json(400, {"error": "invalid_request"})
                return
            with _active_lock:
                process = _active_process if _active_job_id == requested_id else None
            if process is None or process.poll() is not None:
                self._json(404, {"status": "not_running"})
                return
            try:
                os.killpg(process.pid, signal.SIGKILL)
                self._json(202, {"status": "cancelled"})
            except ProcessLookupError:
                self._json(404, {"status": "not_running"})
            return
        if not _job_lock.acquire(blocking=False):
            self._json(429, {"error": "busy"})
            return
        try:
            payload = json.loads(body)
            if not isinstance(payload, dict):
                raise ValueError("invalid_request")
            result = run_voidaccess(payload)
            self._json(200, result)
        except ValueError:
            self._json(400, {"error": "invalid_request"})
        except TimeoutError:
            self._json(504, {"error": "timeout"})
        except Exception:
            self._json(502, {"error": "worker_failed"})
        finally:
            _job_lock.release()


def main() -> None:
    global _shared_secret
    args = sys.argv[1:]
    if args not in ([], ["--check"]):
        raise SystemExit("Usage: voidaccess_worker.py [--check]")
    _shared_secret = _load_shared_secret()
    _validate_runtime(check_tor=args == ["--check"])
    if args == ["--check"]:
        return
    host = os.environ.get("VOIDACCESS_LISTEN_HOST", "127.0.0.1")
    port = int(os.environ.get("VOIDACCESS_LISTEN_PORT", "8766"))
    if host not in {"127.0.0.1", "::1"}:
        raise SystemExit("Refusing a non-loopback listen address")
    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    server.serve_forever(poll_interval=0.5)


if __name__ == "__main__":
    main()
