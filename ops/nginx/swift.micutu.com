# Rate-limit zones: burst allows momentary spikes, excess requests get 429
limit_req_zone $binary_remote_addr zone=scan_limit:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=api_limit:10m  rate=30r/s;

server {
    include snippets/block-dotfiles.conf;
    server_name swift.micutu.com;
    include snippets/cloudflare-realip.conf;

    # The public TLS origin is Cloudflare-only. The geo map uses the original
    # TCP peer, not the visitor address restored by cloudflare-realip.conf.
    # A direct request with forged forwarding headers therefore still gets 403.
    if ($from_cloudflare_origin = 0) { return 403; }

    # ── Security headers ──────────────────────────────────────────────────────
    add_header X-Frame-Options           "DENY" always;
    add_header X-Content-Type-Options    "nosniff" always;
    add_header Referrer-Policy           "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy        "camera=(), microphone=(), geolocation=()" always;
    add_header X-Robots-Tag              "noindex, nofollow" always;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    include snippets/swift-csp.conf;
    add_header Onion-Location "http://5jyd4lflkewyc3gm42uxvi2aryh5g2l4ib2pm5uewpff3ld7yfii5iid.onion$request_uri" always;

    # ── Static frontend ───────────────────────────────────────────────────────
    location /robots.txt {
        root  /srv/swift-vapor/current/frontend;
        access_log off;
    }

    location / {
        root  /srv/swift-vapor/current/frontend;
        index index.html;
        try_files $uri $uri/ /index.html;
    }

    # ── API scan (POST) — stricter rate limit ─────────────────────────────────
    location /api/scan {
        limit_req zone=scan_limit burst=20 nodelay;
        limit_req_status 429;
        client_max_body_size 10k;

        proxy_pass        http://127.0.0.1:8085/scan;
        proxy_http_version 1.1;
        proxy_set_header  Host              $host;
        proxy_set_header  X-Real-IP         $remote_addr;
        proxy_set_header  X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header  X-Forwarded-Proto $scheme;
        proxy_set_header  CF-Connecting-IP  $remote_addr;
    }

    # ── SSE stream (long-lived, unbuffered) ──────────────────────────────────────
    location /api/stream/ {
        limit_req zone=api_limit burst=50 nodelay;
        limit_req_status 429;
        client_max_body_size 10k;
        proxy_buffering      off;
        proxy_cache          off;
        proxy_read_timeout   130s;
        proxy_pass        http://127.0.0.1:8085/stream/;
        proxy_http_version 1.1;
        proxy_set_header  Connection "";
        proxy_set_header  Host              $host;
        proxy_set_header  X-Real-IP         $remote_addr;
        proxy_set_header  X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header  X-Forwarded-Proto $scheme;
        proxy_set_header  CF-Connecting-IP  $remote_addr;
    }

    # Investigation graphs are capped at 512 KB after JSON decoding. Their
    # escaped JSON envelope can be larger, so only these routes receive 1 MB.
    # Vapor independently enforces the same pre-decode collection ceiling.
    location ^~ /api/investigations {
        limit_req zone=api_limit burst=20 nodelay;
        limit_req_status 429;
        client_max_body_size 1m;

        proxy_pass        http://127.0.0.1:8085/investigations;
        proxy_http_version 1.1;
        proxy_set_header  Host              $host;
        proxy_set_header  X-Real-IP         $remote_addr;
        proxy_set_header  X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header  X-Forwarded-Proto $scheme;
        proxy_set_header  CF-Connecting-IP  $remote_addr;
    }

    # ── Health & Metrics (direct, no /api/ prefix) ─────────────────────────
    location /health {
        proxy_pass        http://127.0.0.1:8085/health;
        proxy_http_version 1.1;
        proxy_set_header  Host              $host;
        proxy_set_header  X-Real-IP         $remote_addr;
        proxy_set_header  X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header  X-Forwarded-Proto $scheme;
    }

    location /metrics {
        proxy_pass        http://127.0.0.1:8085/metrics;
        proxy_http_version 1.1;
        proxy_set_header  Host              $host;
        proxy_set_header  X-Real-IP         $remote_addr;
        proxy_set_header  X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header  X-Forwarded-Proto $scheme;
    }

    # ── All other API routes ──────────────────────────────────────────────────
    location /api/ {
        limit_req zone=api_limit burst=50 nodelay;
        limit_req_status 429;
        client_max_body_size 10k;

        proxy_pass        http://127.0.0.1:8085/;
        proxy_http_version 1.1;
        proxy_set_header  Host              $host;
        proxy_set_header  X-Real-IP         $remote_addr;
        proxy_set_header  X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header  X-Forwarded-Proto $scheme;
        proxy_set_header  CF-Connecting-IP  $remote_addr;
    }

    listen 443 ssl; # managed by Certbot
    ssl_certificate     /etc/letsencrypt/live/swift.micutu.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/swift.micutu.com/privkey.pem;
    include             /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam         /etc/letsencrypt/ssl-dhparams.pem;
}

server {
    include snippets/block-dotfiles.conf;
    if ($host = swift.micutu.com) {
        return 301 https://$host$request_uri;
    }
    listen      80;
    server_name swift.micutu.com;
    return      404;
}
