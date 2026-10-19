#!/usr/bin/env bash
# Tells the IndexNow search engines (Bing, Yandex, Seznam, Naver, …) about
# every page in the sitemap, so new and changed pages are crawled in hours
# instead of weeks. Google does not take part; it reads the sitemap.
#
# The ownership key is the one frontend/<key>.txt serves; run this after a
# deploy that changed pages:  scripts/indexnow.sh [https://swift.micutu.com]
set -euo pipefail

SITE="${1:-https://swift.micutu.com}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
key_file="$(find "$ROOT_DIR/frontend" -maxdepth 1 -regextype posix-extended -regex '.*/[0-9a-f]{32}\.txt' -print -quit)"
[[ -n "$key_file" ]] || { echo "indexnow: no key file in frontend/" >&2; exit 1; }
key="$(cat "$key_file")"
[[ "$(basename "$key_file" .txt)" == "$key" ]] || { echo "indexnow: key file name and content differ" >&2; exit 1; }

# The key must be live before engines are asked to trust it.
served="$(curl -fsS "$SITE/$key.txt")" || { echo "indexnow: $SITE/$key.txt is not served yet" >&2; exit 1; }
[[ "$served" == "$key" ]] || { echo "indexnow: served key does not match" >&2; exit 1; }

host="${SITE#https://}"
payload="$(python3 -I - "$ROOT_DIR/frontend/sitemap.xml" "$host" "$key" "$SITE" <<'PY'
import json, sys, xml.etree.ElementTree as ET
sitemap, host, key, site = sys.argv[1:]
ns = {"s": "http://www.sitemaps.org/schemas/sitemap/0.9"}
urls = [loc.text for loc in ET.parse(sitemap).getroot().findall("s:url/s:loc", ns)]
print(json.dumps({"host": host, "key": key, "keyLocation": f"{site}/{key}.txt", "urlList": urls}))
PY
)"
count="$(python3 -I -c 'import json,sys; print(len(json.load(sys.stdin)["urlList"]))' <<< "$payload")"
status="$(curl -sS -o /dev/null -w '%{http_code}' -X POST https://api.indexnow.org/indexnow \
    -H 'Content-Type: application/json; charset=utf-8' --data "$payload")"
echo "indexnow: submitted $count URL(s), HTTP $status"
# 200 accepted, 202 accepted pending key validation; anything else is a failure.
[[ "$status" == "200" || "$status" == "202" ]]
