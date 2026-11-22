#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
nginx=${NGINX_BINARY:-$root/test/nginx-1.27.2/objs/nginx}
image=${ANUBIS_IMAGE:-ghcr.io/techarohq/anubis:v1.28.2}
load_module_line=
if [ -n "${NGINX_LOAD_MODULE:-}" ]; then
    load_module_line="load_module $NGINX_LOAD_MODULE;"
fi
anubis_port=${ANUBIS_TEST_PORT:-18923}
nginx_port=${ANUBIS_NGINX_PORT:-18190}
allow_port=$((nginx_port + 1))
deny_port=$((nginx_port + 2))
tls_anubis_port=$((nginx_port + 3))
tls_waf_port=$((nginx_port + 4))
bad_port=$((nginx_port + 9))
prefix=$(mktemp -d)
container="ngx-waf-anubis-e2e-$$"
nginx_pid=
pass=0
fail=0

cleanup() {
    if [ -n "$nginx_pid" ]; then
        kill -INT "$nginx_pid" 2>/dev/null || true
        wait "$nginx_pid" 2>/dev/null || true
    fi
    docker rm -f "$container" >/dev/null 2>&1 || true
    if [ "${ANUBIS_TEST_KEEP:-0}" = 1 ]; then
        printf 'preserved test directory: %s\n' "$prefix"
    else
        rm -rf "$prefix"
    fi
}
trap cleanup EXIT INT TERM

ok() {
    pass=$((pass + 1))
    printf 'ok   %s\n' "$1"
}

bad() {
    fail=$((fail + 1))
    printf 'FAIL %s\n' "$1"
}

expect_status() {
    local want=$1
    local label=$2
    shift 2
    local got
    got=$(curl -sS -o "$prefix/response" -w '%{http_code}' --max-time 15 "$@")
    if [ "$got" = "$want" ]; then
        ok "$label"
    else
        bad "$label -> $got (want $want)"
    fi
}

if [ ! -x "$nginx" ]; then
    echo "missing nginx binary: $nginx" >&2
    exit 1
fi
if ! command -v docker >/dev/null || ! command -v curl >/dev/null; then
    echo "docker and curl are required" >&2
    exit 1
fi

if ! docker image inspect "$image" >/dev/null 2>&1; then
    docker pull "$image"
fi

mkdir -p "$prefix/www" "$prefix/body"
printf 'backend' >"$prefix/www/index.html"
printf 'backend' >"$prefix/www/wp-login.php"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj '/CN=127.0.0.1' \
    -addext 'subjectAltName=IP:127.0.0.1' \
    -keyout "$prefix/tls.key" -out "$prefix/tls.crt" \
    >/dev/null 2>&1

public_url_env=()
if [ "${ANUBIS_BROWSER:-0}" = 1 ]; then
    public_url_env=(--env 'PUBLIC_URL=http://127.0.0.1')
fi

docker run -d --rm --name "$container" \
    -p "127.0.0.1:$anubis_port:8080" \
    --env 'BIND=:8080' \
    --env 'TARGET= ' \
    --env 'BASE_PREFIX=/base' \
    "${public_url_env[@]}" \
    --env 'POLICY_FNAME=/data/policy.yaml' \
    --volume "$root/test/e2e/anubis-policy.yaml:/data/policy.yaml:ro" \
    "$image" >/dev/null

for _ in $(seq 1 100); do
    if curl -sS -o /dev/null --max-time 1 \
        -H 'Host: example.test' \
        -H 'X-Real-IP: 203.0.113.10' \
        -H 'X-Forwarded-Host: example.test' \
        -H 'X-Forwarded-Proto: http' \
        -H 'X-Forwarded-Uri: /index.html' \
        "http://127.0.0.1:$anubis_port/base/.within.website/x/cmd/anubis/api/check" \
        2>/dev/null
    then
        break
    fi
    sleep 0.1
done

cat >"$prefix/nginx.conf" <<EOF
worker_processes 1;
daemon off;
master_process off;
error_log $prefix/error.log info;
pid $prefix/nginx.pid;
env SSL_CERT_FILE;
$load_module_line

events {
    worker_connections 128;
}

http {
    access_log off;
    client_body_temp_path $prefix/body;
    set_real_ip_from 127.0.0.1;
    real_ip_header X-Real-IP;
    root $prefix/www;

    server {
        listen 127.0.0.1:$nginx_port;
        server_name example.test;
        absolute_redirect off;
        waf on;
        waf_anubis on url=http://127.0.0.1:$anubis_port/base;
        add_header X-Seen-Anubis \$http_x_anubis_status always;
    }

    server {
        listen 127.0.0.1:$allow_port;
        server_name example.test;
        waf on;
        waf_anubis on url=http://127.0.0.1:1;
        add_header X-Seen-Anubis \$http_x_anubis_status always;
    }

    server {
        listen 127.0.0.1:$deny_port;
        server_name example.test;
        waf on;
        waf_anubis on url=http://127.0.0.1:1 on_error=deny;
    }

    server {
        listen 127.0.0.1:$tls_anubis_port ssl;
        ssl_certificate $prefix/tls.crt;
        ssl_certificate_key $prefix/tls.key;
        location / {
            proxy_pass http://127.0.0.1:$anubis_port;
            proxy_set_header Host \$http_host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        }
    }

    server {
        listen 127.0.0.1:$tls_waf_port;
        server_name example.test;
        waf on;
        waf_anubis on url=https://127.0.0.1:$tls_anubis_port/base;
    }
}
EOF

cat >"$prefix/bad-priority.conf" <<EOF
worker_processes 1;
daemon off;
master_process off;
error_log $prefix/bad-priority.log info;
$load_module_line
events { worker_connections 8; }
http {
    server {
        listen 127.0.0.1:$bad_port;
        waf on;
        waf_priority "VERIFY-BOT CC CAPTCHA UNDER-ATTACK MODSECURITY";
    }
}
EOF

cat >"$prefix/bad-scope.conf" <<EOF
worker_processes 1;
daemon off;
master_process off;
error_log $prefix/bad-scope.log info;
$load_module_line
events { worker_connections 8; }
http {
    server {
        listen 127.0.0.1:$((bad_port + 1));
        location /private {
            waf_anubis on url=http://127.0.0.1:$anubis_port;
        }
    }
}
EOF

"$nginx" -t -p "$prefix/" -c "$prefix/nginx.conf" \
    -e "$prefix/config-test.log"

if "$nginx" -t -p "$prefix/" -c "$prefix/bad-priority.conf" \
    -e "$prefix/bad-priority-test.log" 2>"$prefix/bad-priority.err"
then
    bad "five-item waf_priority was accepted"
else
    if grep -q 'must specify the priority of all inspections' \
        "$prefix/bad-priority.err"
    then
        ok "five-item waf_priority is rejected"
    else
        bad "five-item waf_priority failed for the wrong reason"
    fi
fi

if "$nginx" -t -p "$prefix/" -c "$prefix/bad-scope.conf" \
    -e "$prefix/bad-scope-test.log" 2>"$prefix/bad-scope.err"
then
    bad "waf_anubis was accepted in a location"
else
    if grep -q 'directive is not allowed here' "$prefix/bad-scope.err"; then
        ok "waf_anubis is restricted to http/server"
    else
        bad "waf_anubis location check failed for the wrong reason"
    fi
fi

SSL_CERT_FILE="$prefix/tls.crt" "$nginx" -p "$prefix/" -c "$prefix/nginx.conf" \
    -e "$prefix/nginx-error.log" >"$prefix/nginx.out" 2>&1 &
nginx_pid=$!

for _ in $(seq 1 100); do
    if curl -sS -o /dev/null --max-time 1 \
        "http://127.0.0.1:$nginx_port/index.html" 2>/dev/null
    then
        break
    fi
    sleep 0.1
done

base_url="http://127.0.0.1:$nginx_port"
headers=(-H 'Host: example.test' -H 'X-Real-IP: 203.0.113.10')

python3 "$root/test/e2e/anubis-redirect-security.py" --port "$nginx_port"
ok "ambiguous redirect queries are rejected before proxying"

status=$(curl -sS -D "$prefix/challenge.headers" -o "$prefix/challenge.html" \
    -w '%{http_code}' --max-time 15 -A 'Mozilla/5.0' \
    "${headers[@]}" "$base_url/index.html?x=1")
if [ "$status" = 307 ] \
    && grep -qi '^Location: .*\/base\/.within\.website\/?redir=%2Findex\.html%3Fx%3D1' \
        "$prefix/challenge.headers"
then
    ok "unverified request redirects to the same-origin challenge"
else
    bad "unverified request redirect"
fi

status=$(curl -sS -D "$prefix/page.headers" -o "$prefix/page.html" \
    -w '%{http_code}' --max-time 15 -A 'Mozilla/5.0' \
    "${headers[@]}" "$base_url/base/.within.website/?redir=%2Findex.html%3Fx%3D1")
if [ "$status" = 200 ] \
    && grep -qi '^Content-Type: text/html' "$prefix/page.headers" \
    && grep -qi '^Set-Cookie: .*anubis-cookie-verification' "$prefix/page.headers" \
    && grep -q 'Making sure' "$prefix/page.html" \
    && [ "$(grep -ci '^Content-Type:' "$prefix/page.headers")" = 1 ] \
    && [ "$(grep -ci '^Date:' "$prefix/page.headers")" = 1 ]
then
    ok "Anubis challenge page is proxied with cookies and headers"
else
    bad "Anubis challenge page proxy"
    cat "$prefix/page.headers"
fi

status=$(curl -sS -D "$prefix/css.headers" -o "$prefix/xess.css" \
    -w '%{http_code}' --max-time 15 -A 'Mozilla/5.0' \
    "${headers[@]}" \
    "$base_url/base/.within.website/x/xess/xess.min.css?cachebuster=v1.28.2")
css_size=$(wc -c <"$prefix/xess.css")
if [ "$status" = 200 ] \
    && grep -qi '^Content-Type: text/css' "$prefix/css.headers" \
    && [ "$css_size" -gt 100000 ]
then
    ok "large chunked challenge asset is streamed"
else
    bad "large chunked challenge asset"
fi

expect_status 403 "Anubis deny policy is forwarded" \
    -A 'AnubisDenyTest' "${headers[@]}" "$base_url/index.html"
expect_status 200 "auth timeout fails open by default" \
    -A 'Mozilla/5.0' -H 'Host: example.test' -H 'X-Real-IP: 203.0.113.10' \
    -H 'X-Anubis-Status: SPOOF' \
    "http://127.0.0.1:$allow_port/index.html"
allow_status=$(curl -sS -D "$prefix/allow.headers" -o /dev/null \
    -w '%{http_code}' --max-time 15 \
    -A 'Mozilla/5.0' -H 'Host: example.test' -H 'X-Real-IP: 203.0.113.10' \
    -H 'X-Anubis-Status: SPOOF' "http://127.0.0.1:$allow_port/index.html")
if [ "$allow_status" = 200 ] \
    && ! grep -Eqi '^X-Seen-Anubis:[[:space:]]*SPOOF' "$prefix/allow.headers"
then
    ok "client-supplied X-Anubis-* headers are stripped on fail-open"
else
    bad "client-supplied X-Anubis-* headers on fail-open"
fi
expect_status 503 "on_error=deny fails closed" \
    -A 'Mozilla/5.0' -H 'Host: example.test' -H 'X-Real-IP: 203.0.113.10' \
    "http://127.0.0.1:$deny_port/index.html"

python3 "$root/test/e2e/anubis-solve.py" \
    --port "$nginx_port" \
    --host example.test \
    --client 203.0.113.10 \
    --base-prefix /base \
    --protected '/index.html?x=1'
ok "real proof-of-work challenge and auth cookie"

python3 "$root/test/e2e/anubis-solve.py" \
    --port "$nginx_port" \
    --host example.test \
    --client 203.0.113.12 \
    --base-prefix /base \
    --expect-difficulty 4 \
    --pass-redir 'https://example.test/base/.within.website/?redir=%2Fwp-login.php' \
    --protected '/wp-login.php'
ok "challenge keeps the path-specific policy rule for an absolute self redir"

python3 "$root/test/e2e/anubis-solve.py" \
    --port "$tls_waf_port" \
    --host example.test \
    --client 203.0.113.11 \
    --base-prefix /base \
    --protected '/index.html?x=1'
ok "https auth check and challenge proxy"

if [ "${ANUBIS_BROWSER:-0}" = 1 ]; then
    if ! python3 -c 'from playwright.sync_api import sync_playwright' \
        >/dev/null 2>&1
    then
        echo "Python Playwright is required for the browser test" >&2
        exit 1
    fi

    python3 "$root/test/e2e/anubis-browser.py" \
        --url "$base_url/index.html?browser_e2e=1" \
        --expect-text backend \
        --timeout "${ANUBIS_BROWSER_TIMEOUT:-60}"
    ok "real Chromium challenge, redirect and authenticated reuse"
fi

printf '\n%s passed, %s failed\n' "$pass" "$fail"
if [ "$fail" -ne 0 ]; then
    tail -100 "$prefix/nginx-error.log"
    exit 1
fi
