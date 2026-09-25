#!/bin/sh
# A development helper: start nginx with a small configuration and print what a
# bunch of requests do, including the module's own alert log lines.
set -u

root=$(cd "$(dirname "$0")/../.." && pwd)
nginx_bin=${NGINX_BIN:-$root/test/nginx-1.27.2/objs/nginx}
prefix=/tmp/waf-debug
port=18090

rm -rf "$prefix"
mkdir -p "$prefix/conf" "$prefix/logs" "$prefix/html/bp" "$prefix/rules"
cp "$root/assets/rules/"* "$prefix/rules/"
printf '1.1.1.1\n2.0.0.0/8\n' >> "$prefix/rules/ipv4"
printf '3.3.3.3\n4.0.0.0/8\n' >> "$prefix/rules/white-ipv4"
printf 'AAAA::\nBBBB::/16\n' >> "$prefix/rules/ipv6"
printf 'CCCC::\nDDDD::/16\n' >> "$prefix/rules/white-ipv6"
printf '/white/\n' >> "$prefix/rules/white-url"
printf '/white/\n' >> "$prefix/rules/white-referer"
printf 'backend\n' > "$prefix/html/index.html"
printf "bp\n" > "$prefix/html/bp/index.html"; mkdir -p "$prefix/html/ok"; printf "ok\n" > "$prefix/html/ok/index.html"

cat > "$prefix/conf/nginx.conf" <<EOF
worker_processes 1;
daemon off;
error_log logs/error.log info;
pid logs/nginx.pid;
events { worker_connections 64; }
http {
    access_log off;
    client_body_temp_path logs/body;
    set_real_ip_from 127.0.0.0/8;
    real_ip_header X-Real-IP;
    waf_zone name=z size=10m;
    server {
        listen 127.0.0.1:$port;
        root html;

        waf on;
        waf_mode FULL;
        waf_rule_path $prefix/rules/;
        waf_cc_deny on rate=2r/m duration=1h zone=z:cc;

        location /ok {
        }

        location /bp {
            waf_block_page default;
        }

        location /var {
            return 200 "[\$waf_log][\$waf_blocked][\$waf_rule_type][\$waf_rate]";
        }

        location /error {
            return 200 "[\$waf_log][\$waf_blocking_log][\$waf_blocked][\$waf_rule_type]";
        }

        error_page 403 /error;
        error_page 503 /error;
    }
}
EOF

"$nginx_bin" -p "$prefix" -c conf/nginx.conf -t || exit 1
: > "$prefix/logs/error.log"
"$nginx_bin" -p "$prefix" -c conf/nginx.conf > "$prefix/logs/stdout.log" 2>&1 &
nginx_pid=$!
sleep 1

request() {
    printf '%-46s -> %s\n' "$*" "$(curl -s --max-time 5 -o /dev/null -w '%{http_code}' "$@")"
}

request -H 'X-Real-IP: 7.7.7.1' "http://127.0.0.1:$port/"
request -H 'X-Real-IP: 7.7.7.3' "http://127.0.0.1:$port/bp/www.bak"
request -H 'X-Real-IP: 7.7.7.9' "http://127.0.0.1:$port/ok/"
request -H 'X-Real-IP: 7.7.7.9' "http://127.0.0.1:$port/ok/"
request -H 'X-Real-IP: 7.7.7.9' "http://127.0.0.1:$port/ok/"
echo "body /var:            $(curl -s --max-time 5 -H 'X-Real-IP: 7.7.7.10' "http://127.0.0.1:$port/var")"
echo "body blocked via bp:  $(curl -s --max-time 5 -H 'X-Real-IP: 7.7.7.12' "http://127.0.0.1:$port/bp/www.bak" | head -c 40)"
echo "body blocked (error_page): $(curl -s --max-time 5 -H 'X-Real-IP: 7.7.7.11' "http://127.0.0.1:$port/www.bak")"

kill "$nginx_pid" 2>/dev/null
wait "$nginx_pid" 2>/dev/null
echo "--- alerts ---"
grep -a 'ngx_waf' "$prefix/logs/error.log" | tail -20
