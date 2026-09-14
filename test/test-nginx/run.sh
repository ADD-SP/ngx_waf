#!/bin/sh
# Run the nginx integration suite against the built module.
#
# `MODULE_PATH` selects the dynamic module to load, without it the tests
# expect a nginx built with the static module.

set -e

here=$(cd "$(dirname "$0")" && pwd)

if [ -z "$MODULE_TEST_PATH" ]; then
    MODULE_TEST_PATH=$(mktemp -d)
    export MODULE_TEST_PATH
fi

if [ -z "$MODULE_PATH" ]; then
    MODULE_PATH="$here/../nginx-1.27.2/objs/ngx_http_waf_module.so"
fi
if [ ! -f "$MODULE_PATH" ]; then
    MODULE_PATH=""
fi

if [ -z "$TEST_NGINX_BINARY" ]; then
    binary="$here/../nginx-1.27.2/objs/nginx"
    if [ -x "$binary" ]; then
        TEST_NGINX_BINARY="$binary"
        export TEST_NGINX_BINARY
    fi
fi

"$here/init.sh"
exec "$here/start.sh" "$@"
