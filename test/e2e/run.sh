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
# The provider stub that accepts a connection and never answers.
hang_port=18092
hang_pid=""
# The provider stub that answers with a chunked body.
chunked_port=18094
chunked_pid=""

cleanup() {
    if [ -n "$hang_pid" ]; then
        kill "$hang_pid" 2>/dev/null || true
    fi
    if [ -n "$chunked_pid" ]; then
        kill "$chunked_pid" 2>/dev/null || true
    fi
    if [ -f "$prefix/logs/nginx.pid" ]; then
        kill "$(cat "$prefix/logs/nginx.pid")" 2>/dev/null || true
    fi
}
trap cleanup EXIT

rm -rf "$prefix"
mkdir -p "$prefix/conf" "$prefix/logs" "$prefix/html/t" "$prefix/rules"

cp "$root/assets/rules/"* "$prefix/rules/"
# The second block is covered by the first one: the C implementation logs the
# overlap and keeps the configuration, the redundant block is dropped.
printf '1.1.1.1\n2.0.0.0/8\n2.1.0.0/16\n' >> "$prefix/rules/ipv4"
printf '3.3.3.3\n4.0.0.0/8\n'            >> "$prefix/rules/white-ipv4"
printf 'AAAA::\nBBBB::/16\n'             >> "$prefix/rules/ipv6"
printf 'CCCC::\nDDDD::/16\n'             >> "$prefix/rules/white-ipv6"
printf '/white/\n'                       >> "$prefix/rules/white-url"
printf '/white/\n'                       >> "$prefix/rules/white-referer"
# A pattern only PCRE accepts: the rules go through the engine of nginx, like
# the ones of the C implementation did (`rust/src/pcre.rs`).  The leading
# newline ends the last line of the shipped file, which has none.
printf '\n^/(?!allowed/)www\\.pcre$\n'   >> "$prefix/rules/url"
# A certificate for the TLS provider stub; without openssl the TLS case is
# skipped.
# nginx resolves a relative certificate path against the configuration
# directory.
mkdir -p "$prefix/conf/ssl"
if command -v openssl > /dev/null 2>&1; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj '/CN=127.0.0.1' \
        -keyout "$prefix/conf/ssl/key.pem" -out "$prefix/conf/ssl/cert.pem" > /dev/null 2>&1
fi

if [ -n "${MODULE_PATH:-}" ]; then
    # Load the module dynamically instead of using a static build.
    {
        printf 'load_module %s;\n' "$MODULE_PATH"
        cat "$here/nginx.conf"
    } > "$prefix/conf/nginx.conf"
else
    cp "$here/nginx.conf" "$prefix/conf/nginx.conf"
fi

# Every check runs against one worker by default; `E2E_WORKERS=4` makes the
# counters and the action table of the shared memory matter.  `@PREFIX@` is
# substituted so that the configuration can point at the files of this run.
workers=${E2E_WORKERS:-1}
sed -e "s/^worker_processes .*/worker_processes  $workers;/" \
    -e "s|@PREFIX@|$prefix|g" \
    "$prefix/conf/nginx.conf" > "$prefix/conf/nginx.conf.tmp"
mv "$prefix/conf/nginx.conf.tmp" "$prefix/conf/nginx.conf"

printf 'backend\n' > "$prefix/html/index.html"
printf 'static error page\n' > "$prefix/html/403.html"
# The ModSecurity rules of the `waf_priority` servers: one rule in phase 2,
# enough to compare the two orderings (no CRS needed).
printf 'SecRuleEngine On\nSecRule ARGS:test "@streq deny" "id:1,phase:2,deny,status:403,log"\n' \
    > "$prefix/modsec.conf"
# The two rules of the phase comparison: both match `/phase?phase=1`, the first
# one runs in phase 1 and has to answer on its own.
printf 'SecRule REQUEST_URI "@contains /phase" "id:2,phase:1,deny,status:403,log,msg:phase one"\n' \
    >> "$prefix/modsec.conf"
printf 'SecRule ARGS:phase "@streq 1" "id:3,phase:2,redirect:/moved,status:302,log,msg:phase two"\n' \
    >> "$prefix/modsec.conf"
# A second rule file: `waf_modsecurity` takes more than one `file=`, every one
# of them has to reach the library.
printf 'SecRule REQUEST_URI "@contains /second" "id:4,phase:2,deny,status:419,log,msg:second file"\n' \
    > "$prefix/modsec-second.conf"

# A provider that accepts the connection and never answers: the module has to
# give up on its own timeout.  Without python3 the case is skipped.
if command -v python3 > /dev/null 2>&1; then
    python3 - "$hang_port" "$prefix/hang.received" <<'PY' &
import socket
import sys
import threading

# Accept the connections and hold them open, never write a byte back.  Whatever
# a client sends is recorded: a provider request must not reach this stub (its
# TLS handshake never completes, a request written here would be clear text).
received = open(sys.argv[2], "ab", buffering=0)


def hold(connection):
    while True:
        try:
            data = connection.recv(4096)
        except OSError:
            continue  # the timeout fired, the connection stays open
        if not data:
            return
        received.write(data)


server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", int(sys.argv[1])))
server.listen(16)
held = []
while True:
    connection, _ = server.accept()
    held.append(connection)
    connection.settimeout(0.2)
    threading.Thread(target=hold, args=(connection,), daemon=True).start()
PY
    hang_pid=$!
fi

# A provider that answers with a chunked body, like a HTTP/1.1 back end in
# front of the provider would: the module has to decode the framing (the C
# implementation left that to curl).  The answer is split in front of the last
# chunk, with the chunk of the body complete in the first piece: a decoding
# that compacts the buffer as it walks the framing has to be able to read the
# whole framing again when the rest of it arrives.
if command -v python3 > /dev/null 2>&1; then
    python3 - "$chunked_port" <<'PY' &
import socket
import sys
import time

body = b'{"success":true,"score":0.9}'
server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", int(sys.argv[1])))
server.listen(16)

while True:
    connection, _ = server.accept()
    request = b""
    while b"\r\n\r\n" not in request:
        chunk = connection.recv(4096)
        if not chunk:
            break
        request += chunk

    connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n")
    connection.sendall(b"Transfer-Encoding: chunked\r\n\r\n")
    connection.sendall(b"%x\r\n%s\r\n" % (len(body), body))
    time.sleep(0.2)
    connection.sendall(b"0\r\n\r\n")
    connection.close()
PY
    chunked_pid=$!
fi

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

# check_body_slow <expected status> <pattern> <min seconds> <description> <curl args...>
#
# Like `check_body`, but the request is expected to take at least <min> seconds
# (the module gives up on its own timeout), so curl has to wait longer than its
# default here.
check_body_slow() {
    expected=$1
    pattern=$2
    minimum=$3
    description=$4
    shift 4
    started=$(date +%s)
    body=$(curl -s --max-time 20 -w '\n%{http_code}' "$@")
    took=$(( $(date +%s) - started ))
    status=$(printf '%s' "$body" | tail -n 1)
    text=$(printf '%s' "$body" | sed '$d')
    if [ "$status" = "$expected" ] && printf '%s' "$text" | grep -q "$pattern" \
        && [ "$took" -ge "$minimum" ]; then
        pass=$((pass + 1))
        printf 'ok   %-52s %s after %ss\n' "$description" "$status" "$took"
    else
        fail=$((fail + 1))
        printf 'FAIL %-52s %s after %ss (want %s, body: %s)\n' \
            "$description" "$status" "$took" "$expected" "$text"
    fi
}

# check_page <file of rust/data> <description> <curl args...>
#
# The C implementation set the length of its embedded pages with
# `ngx_str_set()`, that is `sizeof(array) - 1`: it never sent the last byte of
# the page.  The response has to be the file of `rust/data/` minus that byte,
# byte for byte.
check_page() {
    expected=$1
    description=$2
    shift 2
    curl -s --max-time 5 -o "$prefix/page.out" "$@"
    head -c -1 "$expected" > "$prefix/page.exp"
    if cmp -s "$prefix/page.out" "$prefix/page.exp"; then
        pass=$((pass + 1))
        printf 'ok   %-52s %s bytes\n' "$description" "$(wc -c < "$prefix/page.out")"
    else
        fail=$((fail + 1))
        printf 'FAIL %-52s %s bytes (want %s)\n' "$description" \
            "$(wc -c < "$prefix/page.out")" "$(wc -c < "$prefix/page.exp")"
    fi
}

base="http://127.0.0.1:$port"

check 200 "allowed request"                  "$base/"
# An allowed request: `$waf_blocking_log` is not found (empty) unless the
# request was blocked, which is what the C implementation reports as well.
check_body 404 '\[true\]\[\]\[false\]\[\]\[\]\[0\]' \
    "variables of an allowed request"        -H 'X-Real-IP: 9.9.9.2' "$base/test0"
check 403 "black url"                        "$base/www.bak"
# The rule files are matched with the PCRE engine of nginx: a look around assert
# (which the `regex` crate cannot compile) has to load and to be honoured.
check 403 "a rule only the PCRE engine accepts" "$base/www.pcre"
check_body 403 '(?!allowed/)' \
    "the blocked page carries that rule"     "$base/www.pcre"
check 404 "the look around assert is honoured" "$base/allowed/www.pcre"
check 403 "black args"                       "$base/?s=onload="
check 403 "black user agent"                 -H 'User-Agent: / SF/' "$base/"
check 403 "black referer"                    -H 'Referer: /www.bak' "$base/"
check 200 "white referer"                    -H 'Referer: /white/www.bak' "$base/"
check 404 "white url"                        "$base/white/www.bak"
check 403 "black cookie"                     -H 'Cookie: s=../' "$base/"
check 403 "black post body"                  -d 'onload=' "$base/"
check 405 "harmless post body"               -d 's=test' "$base/"
# A chunked body has no Content-Length: nginx decodes it, the module still has
# to see it (and the body above the buffer threshold lands in a temp file).
check 403 "black chunked post body" \
    -H 'Transfer-Encoding: chunked' -d 'onload=' "$base/"
check 403 "black url with HEAD"              -I "$base/www.bak"
# Long values are inspected as they are, nothing is truncated on the way to the
# checks (the caches of the C implementation were keyed on the whole value).
long_ua=$(head -c 4096 /dev/zero | tr '\0' a)
check 403 "4k user agent with a rule"        -H "User-Agent: $long_ua/ SF/" "$base/"
check 200 "4k user agent without a rule"     -H "User-Agent: $long_ua" "$base/"
# The body comes from a file: a single command line argument cannot be that
# big (the kernel limits one to 128k), `curl -d @file` reads it instead.
head -c 262144 /dev/zero | tr '\0' a > "$prefix/big.body"
cat "$prefix/big.body" > "$prefix/big.with-rule"
printf 'onload=' >> "$prefix/big.with-rule"
check 403 "256k body with a rule"            -d "@$prefix/big.with-rule" "$base/"
check 405 "256k body without a rule"         -d "@$prefix/big.body" "$base/"
check 403 "black ipv4"                       -H 'X-Real-IP: 1.1.1.1' "$base/"
check 403 "black ipv4 block"                 -H 'X-Real-IP: 2.1.0.0' "$base/"
# `rules/ipv4` has 2.0.0.0/8 and then the covered 2.1.0.0/16: nginx logged the
# overlap while it read the configuration and kept the covering block.
if grep -q 'have overlapping parts.' "$prefix/logs/error.log"; then
    pass=$((pass + 1))
    printf 'ok   %-52s %s\n' "overlapping address block is logged" "kept 2.0.0.0/8"
else
    fail=$((fail + 1))
    printf 'FAIL %-52s (no message in the error log)\n' \
        "overlapping address block is logged"
fi
check_body 403 '\[BLACK-IPV4\]\[2.0.0.0/8\]' \
    "overlapping address block keeps the covering rule" -H 'X-Real-IP: 2.1.0.0' "$base/"
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
check_page "$root/rust/data/block.html" \
    "the block page is byte for byte the C page" "$base/bp/www.bak"
check_page "$root/rust/data/under-attack.html" \
    "the under attack page is byte for byte" "http://127.0.0.1:18099/"
check_body 403 '\[true\]\[true\]\[true\]\[BLACK-URL\]' \
    "variables of a blocked request"         -H 'X-Real-IP: 9.9.9.1' "$base/www.bak"
# An `error_page` that is a file (nginx internally redirects to it) has to be
# the response, the decision must not be applied a second time.
check_body 403 'static error page' \
    "error page from a static file"          "$base/staticerror/www.bak"
# CC protection: rate=2r/m, the third request of the same address is denied.
cc_base="http://127.0.0.1:18084"
cc_headers='X-Real-IP: 9.9.9.3'
check 200 "cc 1st request"                   -H "$cc_headers" "$cc_base/"
check 200 "cc 2nd request"                   -H "$cc_headers" "$cc_base/"
check 503 "cc 3rd request"                   -H "$cc_headers" "$cc_base/"
check_body 503 '\[true\]\[true\]\[true\]\[CC-DENY\]' \
    "cc variables"                           -H "$cc_headers" "$cc_base/"

# A reload re-runs the zone init handler on the very same segment: the counter
# of a client has to survive it (and the handle of the old cycle is released).
reload_ip='X-Real-IP: 9.9.9.30'
check 200 "cc first request before the reload" -H "$reload_ip" "$cc_base/"
"$nginx_bin" -p "$prefix" -c conf/nginx.conf -s reload
sleep 0.5
check 200 "cc second request after the reload" -H "$reload_ip" "$cc_base/"
check 503 "cc denial survives the reload"      -H "$reload_ip" "$cc_base/"
# The patterns of the new cycle were compiled again, in the pool of that cycle.
check 403 "the rules of the reloaded configuration are used" "$base/www.bak"
check 403 "a PCRE rule of the reloaded configuration is used" "$base/www.pcre"

# `rate=02r/m` and `duration=01h`: nginx' `ngx_atoi()` (and therefore the C
# implementation) accepts the leading zeros, the limit is two requests.
padding_base="http://127.0.0.1:18095"
padding_headers='X-Real-IP: 9.9.9.31'
check 200 "cc rate with a leading zero, 1st"   -H "$padding_headers" "$padding_base/"
check 200 "cc rate with a leading zero, 2nd"   -H "$padding_headers" "$padding_base/"
check 503 "cc rate with a leading zero, 3rd"   -H "$padding_headers" "$padding_base/"

# Three shared memory consumers on three different zones of one server.
multi="http://127.0.0.1:18096"
check 200 "cc on its own zone allows the first request" \
    -H 'X-Real-IP: 9.9.9.40' "$multi/"
# `$waf_rate` is the counter of the zone the CC directive named.
check_body 404 '\[2\]\[\]' "cc on its own zone counts the second" \
    -H 'X-Real-IP: 9.9.9.40' "$multi/rate"
check 403 "captcha action table on its own zone challenges" \
    -H 'X-Real-IP: 9.9.9.41' "$multi/www.bak"
check_body 200 'good' "captcha action table on its own zone passes" \
    -H 'X-Real-IP: 9.9.9.41' -X POST -d 'g-recaptcha-response=token' \
    "$multi/captcha"

# The session flow of that challenge answers the "good" of the C
# implementation: the action of the policy carried `ACTION_FLAG_NONE`, so no
# cookie trio is minted and no rule is reported, the entry of the address is
# dropped instead.
check 403 "captcha action session challenges" \
    -H 'X-Real-IP: 9.9.9.44' "$multi/www.bak"
curl -s -D "$prefix/session.headers" -o "$prefix/session.body" --max-time 5 \
    -H 'X-Real-IP: 9.9.9.44' -X POST -d 'g-recaptcha-response=token' \
    "$multi/captcha"
if [ "$(cat "$prefix/session.body")" = "good" ] \
    && ! grep -qi '^Set-Cookie:' "$prefix/session.headers"; then
    pass=$((pass + 1))
    printf 'ok   %-52s %s\n' "captcha action session mints no cookie" "good"
else
    fail=$((fail + 1))
    printf 'FAIL %-52s (headers: %s)\n' "captcha action session mints no cookie" \
        "$(tr -d '\r' < "$prefix/session.headers" | grep -i '^Set-Cookie:' | tr '\n' ' ')"
fi

# The fail counter of that server lives in a fourth zone: `max_fails=1:1m`
# means twenty failures are allowed (`max(max_fails, 20)`), the 21st blocks.
# Counting needs a visitor the action table challenges, so it is blacklisted
# first, and every following request to the verification URL has no token.
check 403 "captcha fail counter visitor is challenged" \
    -H 'X-Real-IP: 9.9.9.42' "$multi/www.bak"
fail_zone_ok=1
attempt=0
while [ "$attempt" -lt 21 ]; do
    attempt=$((attempt + 1))
    status=$(curl -s -o /dev/null --max-time 5 -w '%{http_code}' \
        -H 'X-Real-IP: 9.9.9.42' -X POST -d 'x=1' "$multi/captcha")
    if [ "$attempt" -le 20 ] && [ "$status" != 200 ]; then
        fail_zone_ok=0
    fi
    if [ "$attempt" -eq 21 ] && [ "$status" != 429 ]; then
        fail_zone_ok=0
    fi
done
if [ "$fail_zone_ok" = 1 ]; then
    pass=$((pass + 1))
    printf 'ok   %-52s %s\n' "captcha fail counter on its own zone" "429 after 20"
else
    fail=$((fail + 1))
    printf 'FAIL %-52s (attempt %s was %s)\n' \
        "captcha fail counter on its own zone" "$attempt" "$status"
fi

# A reload reuses the segment of every zone and rebuilds its handle: the CC
# counter of `ngx_waf_z2` continues where it was, and the action table of
# `ngx_waf_z3` still knows the visitor it challenged.
check 403 "captcha action entry before the reload" \
    -H 'X-Real-IP: 9.9.9.43' "$multi/www.bak"
"$nginx_bin" -p "$prefix" -c conf/nginx.conf -s reload
sleep 0.5
check_body 404 '\[3\]\[\]' "cc counter on its zone survives the reload" \
    -H 'X-Real-IP: 9.9.9.40' "$multi/rate"
check_body 200 'bad' "captcha action entry survives the reload" \
    -H 'X-Real-IP: 9.9.9.43' -X POST -d 'x=1' "$multi/captcha"

# `waf_priority` decides which inspection answers first: both servers have the
# ModSecurity rule below and use a blacklisted address, only the order differs.
priority_base="http://127.0.0.1:18097"
default_base="http://127.0.0.1:18098"
check 400 "waf_priority runs ModSecurity before the address list" \
    -H 'X-Real-IP: 1.1.1.1' "$priority_base/?test=deny"
check 403 "the default order keeps the address list first" \
    -H 'X-Real-IP: 1.1.1.1' "$default_base/?test=deny"

# The inspection stops at the first phase of the library that intervenes: the
# phase 1 rule answers even though the phase 2 rule matches as well, and a
# request only the phase 2 rule matches is redirected.
phase_base="http://127.0.0.1:18100"
check 403 "modsecurity stops at the first matching phase" \
    "$phase_base/phase?phase=1"
check 302 "modsecurity redirects when only a later phase matches" \
    "$phase_base/other?phase=1"
headers=$(curl -s -D - -o /dev/null --max-time 5 "$phase_base/other?phase=1")
# nginx turns the relative url of the intervention into an absolute one, like
# it does for the `Location` of any 3xx special response.
if printf '%s' "$headers" | grep -qi '^Location: .*/moved'; then
    pass=$((pass + 1))
    printf 'ok   %-52s %s\n' "modsecurity keeps the url of the intervention" "/moved"
else
    fail=$((fail + 1))
    printf 'FAIL %-52s (headers: %s)\n' "modsecurity keeps the url of the intervention" \
        "$(printf '%s' "$headers" | tr -d '\r' | head -4 | tr '\n' '|')"
fi

# Both rule files of `waf_modsecurity` are loaded, whichever of the two the
# matching rule comes from.
check 403 "modsecurity loads the first rule file" \
    "http://127.0.0.1:18101/phase?phase=1"
check 419 "modsecurity loads the second rule file" \
    "http://127.0.0.1:18101/second"

# A connection over a unix domain socket carries no client address at all: a
# blacklisted URL is still refused, while no address list or counter matches.
check 403 "unix socket request is still inspected" \
    --unix-socket "$prefix/waf.sock" "http://localhost/www.bak"
check 200 "unix socket request is served" \
    --unix-socket "$prefix/waf.sock" "http://localhost/"
check 200 "unix socket connection is not counted" \
    --unix-socket "$prefix/waf.sock" "http://localhost/"

# `waf_mode FULL !GET` clears the bit of the method: the URL list is gated by
# it, the address list is not, so the blacklist still answers.
check 403 "mode without the GET bit keeps the address list" \
    -H 'X-Real-IP: 1.1.1.1' "http://127.0.0.1:18102/"
check 404 "mode without the GET bit skips the URL list" \
    -H 'X-Real-IP: 9.9.9.60' "http://127.0.0.1:18102/www.bak"

# The provider answers with a chunked body: the module has to decode it.
check_body 200 'good' "captcha accepts a chunked provider answer" \
    -X POST -d 'g-recaptcha-response=token' "http://127.0.0.1:18103/captcha"

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

# Captcha: a visitor without cookies is challenged, a token the provider
# accepts mints the cookies, and a visitor that presents them is let through.
cap="http://127.0.0.1:18091"
check 503 "captcha challenges a visitor without cookies" "$cap/"

headers=$(curl -s -D - -o /dev/null --max-time 5 -X POST \
    -d 'g-recaptcha-response=token' "$cap/captcha")
body=$(printf '%s' "$headers" | tail -n 1)
cookies=$(printf '%s' "$headers" \
    | awk '/^Set-Cookie:/ { gsub(/\r/, ""); n = split($2, kv, "="); printf "%s=%s; ", kv[1], kv[2] }' \
    | sed 's/; $//')
if printf '%s' "$headers" | grep -qi '^Set-Cookie: __waf_captcha_hmac=' && [ -n "$cookies" ]; then
    pass=$((pass + 1))
    printf 'ok   %-52s %s\n' "captcha mints the cookie trio" "3 cookies"
else
    fail=$((fail + 1))
    printf 'FAIL %-52s (headers: %s)\n' "captcha mints the cookie trio" "$(printf '%s' "$headers" | head -3 | tr '\n' ' ')"
fi
check_body 200 'good' "captcha accepts the token" \
    -X POST -d 'g-recaptcha-response=token' "$cap/captcha"
# The location that answers that POST has no `waf_captcha` of its own, so the
# provider endpoint (and the verification URL) came from the server level
# through the configuration merge.
check_body 200 'good' "captcha inherits the provider endpoint" \
    -X POST -d 'g-recaptcha-response=token' "$cap/captcha"
check 200 "captcha lets a verified visitor through" -H "Cookie: $cookies" "$cap/"
check 200 "captcha lets a verified visitor reach the verify url" \
    -H "Cookie: $cookies" "$cap/captcha"

# The other provider answers: refused, unreachable, invalid and a low v3 score.
check_body 200 'bad' "captcha rejects a refused token" \
    -X POST -d 'g-recaptcha-response=token' "$cap/bad/captcha"
check_body 200 'bad' "captcha survives an unreachable provider" \
    -X POST -d 'g-recaptcha-response=token' "$cap/err/captcha"
check_body 200 'bad' "captcha survives an invalid answer" \
    -X POST -d 'g-recaptcha-response=token' "$cap/junk/captcha"
check_body 200 'bad' "captcha v3 rejects a low score" \
    -X POST -d 'g-recaptcha-response=token' "$cap/v3/captcha"
if [ -s "$prefix/conf/ssl/cert.pem" ]; then
    check_body 200 'good' "captcha reaches an https provider" \
        -X POST -d 'g-recaptcha-response=token' "$cap/tls/captcha"
    # The provider only accepts a client that sent its host name as the SNI, so
    # this fails when the name is not terminated properly.
    check_body 200 'good' "captcha sends the host name as SNI" \
        -X POST -d 'g-recaptcha-response=token' "$cap/tlsname/captcha"
fi

# The stub of this script accepts the connection and never answers: the module
# has to give up on its own timeout (5s), fail closed and keep serving.
if [ -n "$hang_pid" ]; then
    check_body_slow 200 'bad' 5 "captcha provider timeout fails closed" \
        -X POST -d 'g-recaptcha-response=token' "$cap/hang/captcha"
    check 200 "the worker survives a provider timeout" "$base/"

    # The same stub over TLS: the handshake never completes, and the request
    # (the token and the secret) must not be written into the socket in clear
    # text while the handshake is pending.
    before=$(wc -c < "$prefix/hang.received")
    check_body_slow 200 'bad' 5 "captcha tls handshake timeout fails closed" \
        -X POST -d 'g-recaptcha-response=token' "$cap/tlshang/captcha"
    # Only what the TLS connection wrote: the plain provider request above went
    # to the same stub and is supposed to carry the token and the secret.
    tail -c +$((before + 1)) "$prefix/hang.received" > "$prefix/hang.tls"
    if grep -q 'secret' "$prefix/hang.tls"; then
        fail=$((fail + 1))
        printf 'FAIL %-52s (the request reached the stub)\n' \
            "captcha never writes the request before the handshake"
    else
        pass=$((pass + 1))
        printf 'ok   %-52s %s\n' \
            "captcha never writes the request before the handshake" "no clear text"
    fi
fi

# `waf_action X=CAPTCHA` with the captcha inspection off: the action table
# challenges, the token is verified by the (inherited) provider and the visitor
# is let through.
action_cap="http://127.0.0.1:18093"
action_header='X-Real-IP: 9.9.9.20'
check 403 "captcha action table challenges the first request" \
    -H "$action_header" "$action_cap/www.bak"
check_body 200 'good' "captcha action table is solved with the provider" \
    -H "$action_header" -X POST -d 'g-recaptcha-response=token' "$action_cap/captcha"

# A `waf_captcha` without `api=` uses the default endpoint of its provider: the
# configuration has to load and the request has to fail closed when the
# provider is out of reach.
check_body_slow 200 'bad' 0 "captcha without api= fails closed" \
    -X POST -d 'g-recaptcha-response=token' "$action_cap/default/captcha"

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
