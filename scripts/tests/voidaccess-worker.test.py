#!/usr/bin/python3
"""Black-box contract test for the loopback VoidAccess adapter."""

from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def signature(secret: str, timestamp: str, method: str, path: str, body: bytes) -> str:
    message = (
        timestamp.encode() + b"\n" + method.encode() + b"\n"
        + path.encode() + b"\n" + body
    )
    return hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()


def request(port: int, secret: str, path: str, payload: dict | None):
    body = b"" if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    timestamp = str(int(time.time()))
    headers = {
        "Content-Length": str(len(body)),
        "X-DFT-Timestamp": timestamp,
        "X-DFT-Signature": signature(secret, timestamp, "POST", path, body),
    }
    if body:
        headers["Content-Type"] = "application/json"
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    connection.request("POST", path, body=body, headers=headers)
    response = connection.getresponse()
    data = response.read()
    connection.close()
    return response.status, json.loads(data)


def health(port: int, secret: str) -> int:
    timestamp = str(int(time.time()))
    path = "/health"
    headers = {
        "X-DFT-Timestamp": timestamp,
        "X-DFT-Signature": signature(secret, timestamp, "GET", path, b""),
    }
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
    connection.request("GET", path, headers=headers)
    response = connection.getresponse()
    response.read()
    connection.close()
    return response.status


def main() -> None:
    repository = Path(__file__).resolve().parents[2]
    worker = repository / "worker" / "voidaccess_worker.py"
    secret = "integration-test-secret-at-least-32-bytes"
    port = free_port()

    with tempfile.TemporaryDirectory(prefix="voidaccess-worker-test-") as temp:
        fake = Path(temp) / "voidaccess"
        fake.write_text(
            """#!/usr/bin/python3
import json, pathlib, sys, time
target = sys.argv[sys.argv.index('investigate') + 1]
out = pathlib.Path(sys.argv[sys.argv.index('--output') + 1])
if target == 'slowuser': time.sleep(30)
payload = {
  'entities': [{
    'id': 'e1', 'entity_type': 'EMAIL_ADDRESS', 'value': 'person@example.test',
    'confidence': 0.8, 'corroborating_sources': 'onion-search',
    'context_snippet': 'must never cross the boundary',
    'source_url': 'http://secret-example.onion/page'
  }, {
    'id': 'e2', 'entity_type': 'DOMAIN', 'value': 'example.test',
    'confidence': 0.7, 'corroborating_sources': 'onion-search'
  }, {
    'id': 'e3', 'entity_type': 'GITHUB_TOKEN', 'value': 'ghp_live_secret',
    'confidence': 0.9, 'corroborating_sources': 'onion-search'
  }, {
    'id': 'e4', 'entity_type': 'ONION_URL',
    'value': 'http://hidden-service.onion/private?q=secret',
    'confidence': 0.6, 'corroborating_sources': 'onion-search'
  }, {
    'id': 'e5', 'entity_type': 'HTML_SNIPPET', 'value': '<script>bad()</script>',
    'confidence': 1.0, 'corroborating_sources': 'onion-search'
  }, {
    'id': 'e6', 'entity_type': 'STRIPE_KEY', 'value': 'sk_live_secret',
    'confidence': 0.9, 'corroborating_sources': 'onion-search'
  }],
  'relationships': [{
    'entity_a_id': 'e1', 'entity_b_id': 'e2',
    'relationship_type': 'USES', 'confidence': 0.6
  }],
  'pages_scraped': [{'text': 'raw dark-web page'}]
}
(out / 'result.json').write_text(json.dumps(payload))
""",
            encoding="utf-8",
        )
        fake.chmod(0o700)
        environment = {
            **os.environ,
            "VOIDACCESS_SHARED_SECRET": secret,
            "VOIDACCESS_EXECUTABLE": str(fake),
            # /bin/true accepts the preflight's `-c` arguments, giving this
            # adapter contract test a tiny fake NLP runtime without weakening
            # the production check.
            "VOIDACCESS_PYTHON": "/bin/true",
            "VOIDACCESS_LISTEN_PORT": str(port),
            "VOIDACCESS_JOB_TIMEOUT_SECONDS": "60",
        }
        process = subprocess.Popen(
            [sys.executable, str(worker)],
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            for _ in range(100):
                try:
                    if health(port, secret) == 200:
                        break
                except OSError:
                    time.sleep(0.05)
            else:
                raise AssertionError("worker did not become healthy")

            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
            connection.request("GET", "/health")
            assert connection.getresponse().status == 401
            connection.close()

            job_id = str(uuid.uuid4())
            payload = {
                "jobID": job_id,
                "target": "person@example.test",
                "targetKind": "email",
                "depth": "shallow",
                "useTor": True,
                "useLLM": False,
            }
            status, result = request(port, secret, "/v1/investigations", payload)
            assert status == 200, (status, result)
            assert result["schemaVersion"] == 1
            assert len(result["findings"]) == 5
            assert result["findings"][0]["type"] == "email"
            assert any(
                finding["type"] == "credential_exposure"
                and finding["value"] == "github token detected"
                for finding in result["findings"]
            )
            assert any(
                finding["type"] == "onion_service"
                and finding["value"] == "hidden-service.onion"
                for finding in result["findings"]
            )
            assert result["relationships"][0]["type"] == "USES"
            serialized = json.dumps(result)
            assert "context_snippet" not in serialized
            assert "pages_scraped" not in serialized
            assert "secret-example.onion" not in serialized
            assert "ghp_live_secret" not in serialized
            assert "sk_live_secret" not in serialized
            assert "/private" not in serialized
            assert "<script>" not in serialized

            slow_id = str(uuid.uuid4())
            slow_payload = {
                "jobID": slow_id,
                "target": "slowuser",
                "targetKind": "username",
                "depth": "shallow",
                "useTor": True,
                "useLLM": False,
            }
            background: list[tuple[int, dict]] = []
            thread = threading.Thread(
                target=lambda: background.append(
                    request(port, secret, "/v1/investigations", slow_payload)
                )
            )
            thread.start()
            time.sleep(0.25)
            cancel_status, _ = request(
                port, secret, f"/v1/investigations/{slow_id}/cancel", None
            )
            assert cancel_status == 202, cancel_status
            thread.join(timeout=5)
            assert not thread.is_alive(), "cancel did not terminate the child process"
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

    print("VoidAccess worker contract tests passed.")


if __name__ == "__main__":
    main()
