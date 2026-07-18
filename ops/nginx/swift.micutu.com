# Rate-limit zones: burst allows momentary spikes, excess requests get 429
limit_req_zone $binary_remote_addr zone=scan_limit:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=api_limit:10m  rate=30r/s;

server {
    include snippets/block-dotfiles.conf;
    server_name swift.micutu.com;
    include snippets/cloudflare-realip.conf;

    # ── Security headers ──────────────────────────────────────────────────────
    add_header X-Frame-Options           "DENY" always;
    add_header X-Content-Type-Options    "nosniff" always;
    add_header Referrer-Policy           "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy        "camera=(), microphone=(), geolocation=()" always;
    add_header X-Robots-Tag              "noindex, nofollow" always;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'sha256-v/NV7R0aivQOsk4Ocysn9RMPfGaXLPOYQ9tcOXwz9BU=' 'sha256-HVMRInLymOUvzxk69s78aesdpKW0n08X2rajXAgffE8=' 'sha256-C186Ihkl90gJgpfSXdDuV+UBFagxzDxeNwrToscwOpc='; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://*.tile.openstreetmap.org; connect-src 'self' ; font-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self';" always;

    # ── Static frontend ───────────────────────────────────────────────────────
    location /robots.txt {
        root  /home/micu/swift+vapor/frontend;
        access_log off;
    }

    location / {
        root  /home/micu/swift+vapor/frontend;
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
    # OCSP stapling — server fetches the revocation status so the client never
    # contacts the CA (privacy) and the TLS handshake is faster.
    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_trusted_certificate /etc/letsencrypt/live/swift.micutu.com/chain.pem;
    resolver 127.0.0.53 valid=300s;
    resolver_timeout 5s;
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
