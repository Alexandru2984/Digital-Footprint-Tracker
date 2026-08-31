#!/usr/bin/env python3
"""Every proxied location in the swift vhosts must set the forwarding headers.

`Request.clientIP` trusts `X-Real-IP` (and then `CF-Connecting-IP`) whenever the
socket peer is loopback — which nginx always is. A `location` that proxies
without overwriting those headers therefore lets the client choose the address
the application rate-limits and attributes on.

That is not a hypothesis. The onion vhost's `/health` and `/metrics` were
written without the header lines while every other location had them, because
the block was copied by hand into each location. This check makes the omission
fail instead of waiting to be noticed.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]

VHOSTS = {
    ROOT / "ops/nginx/swift.micutu.com": "snippets/swift-proxy-headers.conf",
    ROOT / "ops/nginx/swift-onion.conf": "snippets/swift-onion-proxy-headers.conf",
}

LOCATION = re.compile(r"^\s*location\s+(?P<spec>[^{]+?)\s*\{", re.MULTILINE)


def proxied_locations_missing_headers(text: str, required_include: str):
    """Return the spec of every location that proxies without the headers.

    A location satisfies the contract either by including the shared snippet
    (the repository form) or by carrying the `X-Real-IP` line directly — which
    is what `nginx -T` shows, since it inlines every include. One function can
    therefore check the checked-in files and the configuration actually loaded.
    """
    missing = []
    for match in LOCATION.finditer(text):
        depth, index = 0, match.end() - 1
        while index < len(text):
            if text[index] == "{":
                depth += 1
            elif text[index] == "}":
                depth -= 1
                if depth == 0:
                    break
            index += 1
        body = text[match.end():index]
        if "proxy_pass" not in body:
            continue
        satisfied = (f"include {required_include};" in body
                     or "proxy_set_header X-Real-IP" in " ".join(body.split()))
        if not satisfied:
            missing.append(match.group("spec").strip())
    return missing


def self_test() -> None:
    good = """
    server {
        location /a { return 404; }
        location /b {
            proxy_pass http://127.0.0.1:1/;
            include snippets/x.conf;
        }
    }
    """
    bad = """
    server {
        location /c {
            proxy_pass http://127.0.0.1:1/;
            proxy_set_header Host $host;
        }
    }
    """
    assert proxied_locations_missing_headers(good, "snippets/x.conf") == [], \
        "a compliant location was flagged"
    assert proxied_locations_missing_headers(bad, "snippets/x.conf") == ["/c"], \
        "a location proxying without the include was not detected"


def live_configuration() -> int:
    """Check the configuration nginx has actually loaded, not the repository.

    `nginx -T` does not inline includes — it prints each included file as its
    own section — so the deployed vhost still shows the `include` line and the
    same contract applies. The snippet's own section is checked too: an include
    of an empty file would otherwise satisfy every location at once.

    Requires root, so it is opt-in and never runs in CI. It is the only form of
    this check that would notice a vhost edited on the host and never brought
    back to the repository — which is exactly what had happened once already.
    """
    import subprocess

    dump = subprocess.run(["nginx", "-T"], capture_output=True, text=True, check=True).stdout
    sections = {}
    current = None
    for line in dump.splitlines():
        if line.startswith("# configuration file "):
            current = line[len("# configuration file "):].rstrip(":")
            sections[current] = []
        elif current is not None:
            sections[current].append(line)
    sections = {name: "\n".join(body) for name, body in sections.items()}

    live = {
        "/etc/nginx/sites-enabled/swift.micutu.com": "snippets/swift-proxy-headers.conf",
        "/etc/nginx/sites-enabled/swift-onion.conf": "snippets/swift-onion-proxy-headers.conf",
    }
    failures = 0
    for path, required_include in live.items():
        if path not in sections:
            print(f"{path}: not present in the loaded configuration", file=sys.stderr)
            failures += 1
            continue
        missing = proxied_locations_missing_headers(sections[path], required_include)
        if missing:
            failures += 1
            print(f"{path}: {len(missing)} live proxied location(s) without the headers",
                  file=sys.stderr)
            for spec in missing:
                print(f"  - location {spec}", file=sys.stderr)
            continue

        snippet = "/etc/nginx/" + required_include
        if "proxy_set_header" not in sections.get(snippet, "") or \
                "X-Real-IP" not in sections.get(snippet, ""):
            print(f"{snippet}: loaded but does not set X-Real-IP", file=sys.stderr)
            failures += 1
            continue
        print(f"{path}: {sections[path].count('proxy_pass')} live proxied location(s), "
              f"all including a snippet that pins X-Real-IP")
    return 1 if failures else 0


def main() -> int:
    self_test()
    if "--live" in sys.argv[1:]:
        return live_configuration()
    failures = 0
    for path, required_include in VHOSTS.items():
        text = path.read_text(encoding="utf-8")
        missing = proxied_locations_missing_headers(text, required_include)
        proxied = text.count("proxy_pass")
        if missing:
            failures += 1
            print(f"{path.relative_to(ROOT)}: {len(missing)} proxied location(s) "
                  f"without `include {required_include};`", file=sys.stderr)
            for spec in missing:
                print(f"  - location {spec}", file=sys.stderr)
        else:
            print(f"{path.relative_to(ROOT)}: {proxied} proxied location(s), "
                  f"all setting forwarding headers")
    if failures:
        return 1
    print("nginx proxy header contract tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
