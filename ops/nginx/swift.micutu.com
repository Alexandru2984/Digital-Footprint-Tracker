# Rate-limit zones: burst allows momentary spikes, excess requests get 429
limit_req_zone $binary_remote_addr zone=scan_limit:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=api_limit:10m  rate=30r/s;

server {
    include snippets/block-dotfiles.conf;
    server_name swift.micutu.com;

    location ^~ /.well-known/acme-challenge/ {
        root /var/www/letsencrypt;
        default_type "text/plain";
        try_files $uri =404;
    }
    # The Cloudflare real-IP trust list is deliberately not re-included at server
    # level. It is loaded once at http level from conf.d, and `set_real_ip_from` is an
    # array directive: a server block that declares its own list *replaces* the
    # inherited one rather than adding to it. Identical content made it harmless,
    # but the invariant is enforced by scripts/tests/production-boundaries.test.sh
    # and production had drifted away from it.

    # Reject direct-to-origin TLS traffic. $realip_remote_addr retains the
    # original TCP peer before the trusted Cloudflare real-IP rewrite.
    set $swift_origin_allowed $from_cloudflare_origin;
    if ($swift_origin_allowed = 0) {
        return 403;
    }

    # ── Security headers ──────────────────────────────────────────────────────
    add_header X-Frame-Options           "DENY" always;
    add_header X-Content-Type-Options    "nosniff" always;
    add_header Referrer-Policy           "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy        "camera=(), microphone=(), geolocation=()" always;
    add_header X-Robots-Tag              "index, follow" always;
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
        include snippets/swift-proxy-headers.conf;
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
        proxy_set_header  Connection "";
        include snippets/swift-proxy-headers.conf;
    }

    # Investigation graphs are capped at 512 KB after JSON decoding. Their
    # escaped JSON envelope can be larger, so only these routes receive 1 MB.
    # Vapor independently enforces the same pre-decode collection ceiling.
    location ^~ /api/investigations {
        limit_req zone=api_limit burst=20 nodelay;
        limit_req_status 429;
        client_max_body_size 1m;

        proxy_pass        http://127.0.0.1:8085/investigations;
        include snippets/swift-proxy-headers.conf;
    }

    # ── Health & Metrics (direct, no /api/ prefix) ─────────────────────────
    # These two were the only proxied locations without a limit_req. Liveness is
    # cheap but unauthenticated; /metrics is authenticated (bearer token or admin
    # session) and runs more than a dozen COUNT(*) queries per call, so neither
    # should be the one door in this file without a bound on it.
    location /health {
        limit_req zone=api_limit burst=20 nodelay;
        limit_req_status 429;
        proxy_pass        http://127.0.0.1:8085/health;
        include snippets/swift-proxy-headers.conf;
    }

    # Database readiness is an internal deploy signal, never a public endpoint.
    # /api/ready would otherwise be stripped to /ready by the generic /api/
    # proxy and appear local to Vapor because nginx connects over loopback.
    location = /ready     { return 404; }
    location = /api/ready { return 404; }

    location /metrics {
        limit_req zone=api_limit burst=20 nodelay;
        limit_req_status 429;
        proxy_pass        http://127.0.0.1:8085/metrics;
        include snippets/swift-proxy-headers.conf;
    }

    # ── All other API routes ──────────────────────────────────────────────────
    location /api/ {
        limit_req zone=api_limit burst=50 nodelay;
        limit_req_status 429;
        client_max_body_size 10k;

        proxy_pass        http://127.0.0.1:8085/;
        include snippets/swift-proxy-headers.conf;
    }

    listen 443 ssl; # managed by Certbot
    ssl_certificate     /etc/letsencrypt/live/swift.micutu.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/swift.micutu.com/privkey.pem;
    include             /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam         /etc/letsencrypt/ssl-dhparams.pem;
}

server {
    include snippets/block-dotfiles.conf;
    location / {
        return 301 https://$host$request_uri;
    }
    listen      80;
    server_name swift.micutu.com;

    location ^~ /.well-known/acme-challenge/ {
        root /var/www/letsencrypt;
        default_type "text/plain";
        try_files $uri =404;
    }
    return      404;
}
