#!/bin/sh
# End to end checks against a real nginx build.
#
#   NGINX_BIN=/path/to/objs/nginx test/e2e/run.sh
#
# The fixtures mirror test/test-nginx/template/*.t: the rule files are the ones
# of assets/rules plus the extra entries test/test-nginx/init.sh appends.

set -u

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
prefix=${E2E_PREFIX:-$(mktemp -d)}
nginx_bin=${NGINX_BIN:-$root/test/nginx-1.27.2/objs/nginx}
port=18080

cleanup() {
    if [ -f "$prefix/logs/nginx.pid" ]; then
        kill "$(cat "$prefix/logs/nginx.pid")" 2>/dev/null || true
    fi
}
trap cleanup EXIT

rm -rf "$prefix"
mkdir -p "$prefix/conf" "$prefix/logs" "$prefix/html/t" "$prefix/rules"

cp "$root/assets/rules/"* "$prefix/rules/"
printf '1.1.1.1\n2.0.0.0/8\n'            >> "$prefix/rules/ipv4"
printf '3.3.3.3\n4.0.0.0/8\n'            >> "$prefix/rules/white-ipv4"
printf 'AAAA::\nBBBB::/16\n'             >> "$prefix/rules/ipv6"
printf 'CCCC::\nDDDD::/16\n'             >> "$prefix/rules/white-ipv6"
printf '/white/\n'                       >> "$prefix/rules/white-url"
printf '/white/\n'                       >> "$prefix/rules/white-referer"
if [ -n "${MODULE_PATH:-}" ]; then
    # Load the module dynamically instead of using a static build.
    {
        printf 'load_module %s;\n' "$MODULE_PATH"
        cat "$here/nginx.conf"
    } > "$prefix/conf/nginx.conf"
else
    cp "$here/nginx.conf" "$prefix/conf/nginx.conf"
fi
printf 'backend\n' > "$prefix/html/index.html"

"$nginx_bin" -p "$prefix" -c conf/nginx.conf -t > /dev/null || exit 1
"$nginx_bin" -p "$prefix" -c conf/nginx.conf > "$prefix/logs/stdout.log" 2>&1 &
nginx_pid=$!

i=0
while [ "$i" -lt 50 ]; do
    if curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$port/"; then
        break
    fi
    i=$((i + 1))
    sleep 0.1
done

if [ "$i" -ge 50 ]; then
    echo "nginx did not become reachable, error log:"
    tail -n 20 "$prefix/logs/error.log"
    tail -n 5 "$prefix/logs/stdout.log"
    exit 1
fi

echo "nginx is running (pid $nginx_pid)"

pass=0
fail=0

# check <expected status> <description> <curl args...>
check() {
    expected=$1
    description=$2
    shift 2
    status=$(curl -s -o /dev/null --max-time 5 -w '%{http_code}' "$@")
    if [ "$status" = "$expected" ]; then
        pass=$((pass + 1))
        printf 'ok   %-52s %s\n' "$description" "$status"
    else
        fail=$((fail + 1))
        printf 'FAIL %-52s %s (want %s)\n' "$description" "$status" "$expected"
    fi
}

# check_body <expected status> <pattern> <description> <curl args...>
check_body() {
    expected=$1
    pattern=$2
    description=$3
    shift 3
    body=$(curl -s --max-time 5 -w '\n%{http_code}' "$@")
    status=$(printf '%s' "$body" | tail -n 1)
    text=$(printf '%s' "$body" | sed '$d')
    if [ "$status" = "$expected" ] && printf '%s' "$text" | grep -q "$pattern"; then
        pass=$((pass + 1))
        printf 'ok   %-52s %s\n' "$description" "$status"
    else
        fail=$((fail + 1))
        printf 'FAIL %-52s %s (want %s, body: %s)\n' "$description" "$status" "$expected" "$text"
    fi
}

base="http://127.0.0.1:$port"

check 200 "allowed request"                  "$base/"
# An allowed request: `$waf_blocking_log` is not found (empty) unless the
# request was blocked, which is what the C implementation reports as well.
check_body 404 '\[true\]\[\]\[false\]\[\]\[\]\[0\]' \
    "variables of an allowed request"        -H 'X-Real-IP: 9.9.9.2' "$base/test0"
check 403 "black url"                        "$base/www.bak"
check 403 "black args"                       "$base/?s=onload="
check 403 "black user agent"                 -H 'User-Agent: / SF/' "$base/"
check 403 "black referer"                    -H 'Referer: /www.bak' "$base/"
check 200 "white referer"                    -H 'Referer: /white/www.bak' "$base/"
check 404 "white url"                        "$base/white/www.bak"
check 403 "black cookie"                     -H 'Cookie: s=../' "$base/"
check 403 "black post body"                  -d 'onload=' "$base/"
check 405 "harmless post body"               -d 's=test' "$base/"
check 403 "black ipv4"                       -H 'X-Real-IP: 1.1.1.1' "$base/"
check 403 "black ipv4 block"                 -H 'X-Real-IP: 2.1.0.0' "$base/"
check 403 "black ipv4 host bit"              -H 'X-Real-IP: 2.0.0.1' "$base/"
check 404 "white ipv4"                       -H 'X-Real-IP: 3.3.3.3' "$base/www.bak"
check 404 "white ipv4 block"                 -H 'X-Real-IP: 4.1.0.0' "$base/www.bak"
check 403 "black ipv6"                       -H 'X-Real-IP: AAAA::' "$base/"
check 403 "black ipv6 block"                 -H 'X-Real-IP: BBBB::1' "$base/"
check 404 "white ipv6"                       -H 'X-Real-IP: CCCC::' "$base/www.bak"
check 404 "white ipv6 block"                 -H 'X-Real-IP: DDDD::1' "$base/www.bak"
check 404 "waf off"                          "http://127.0.0.1:18082/www.bak"
check 404 "waf bypass"                       "http://127.0.0.1:18081/www.bak"
check 404 "mode without the URL bit"         "http://127.0.0.1:18083/www.bak"
check_body 403 'WAF' "block page"            "$base/bp/www.bak"
check_body 403 '\[true\]\[true\]\[true\]\[BLACK-URL\]' \
    "variables of a blocked request"         -H 'X-Real-IP: 9.9.9.1' "$base/www.bak"
# CC protection: rate=2r/m, the third request of the same address is denied.
cc_base="http://127.0.0.1:18084"
cc_headers='X-Real-IP: 9.9.9.3'
check 200 "cc 1st request"                   -H "$cc_headers" "$cc_base/"
check 200 "cc 2nd request"                   -H "$cc_headers" "$cc_base/"
check 503 "cc 3rd request"                   -H "$cc_headers" "$cc_base/"
check_body 503 '\[true\]\[true\]\[true\]\[CC-DENY\]' \
    "cc variables"                           -H "$cc_headers" "$cc_base/"

# `waf_action` must not disarm the triggers it does not mention.
check 403 "waf_action cc_deny keeps the blacklist" \
    -H 'X-Real-IP: 9.9.9.10' "http://127.0.0.1:18085/www.bak"
check 200 "waf_action cc_deny allows the first request" \
    -H 'X-Real-IP: 9.9.9.11' "http://127.0.0.1:18085/"
check 400 "waf_action cc_deny uses the configured status" \
    -H 'X-Real-IP: 9.9.9.11' "http://127.0.0.1:18085/"
check 405 "waf_action blacklist uses the configured status" \
    -H 'X-Real-IP: 9.9.9.12' "http://127.0.0.1:18086/www.bak"
check 200 "waf_action blacklist allows the first request" \
    -H 'X-Real-IP: 9.9.9.13' "http://127.0.0.1:18086/"
check 503 "waf_action blacklist keeps the cc denial" \
    -H 'X-Real-IP: 9.9.9.13' "http://127.0.0.1:18086/"
check 500 "cc without a zone blocks" \
    -H 'X-Real-IP: 9.9.9.14' "http://127.0.0.1:18087/"

# Friendly crawler verification: without a resolver the address cannot be
# checked, so a crawler user agent is a fake one.
check 403 "verify_bot strict blocks a fake bot" \
    -H 'User-Agent: Googlebot' "http://127.0.0.1:18088/"
check 403 "verify_bot strict blocks a fake bingbot" \
    -H 'User-Agent: bingbot' "http://127.0.0.1:18088/"
check 200 "verify_bot strict lets a normal client through" \
    -H 'User-Agent: curl/8.0' "http://127.0.0.1:18088/"
check 200 "verify_bot on allows a fake bot" \
    -H 'User-Agent: Googlebot' "http://127.0.0.1:18089/"
check 200 "verify_bot on allows a normal client" \
    -H 'User-Agent: curl/8.0' "http://127.0.0.1:18089/"

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
