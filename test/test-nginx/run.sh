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

# `MODULE_PATH` is only used when the caller set it: a tree that built the
# dynamic module as well still has a static nginx next to the `.so`, and nginx
# refuses to load a module it was linked with.
# start.sh runs as a child process, so it only sees the variable when it is
# exported.
export MODULE_PATH

if [ -z "$TEST_NGINX_BINARY" ]; then
    binary="$here/../nginx-1.27.2/objs/nginx"
    if [ -x "$binary" ]; then
        TEST_NGINX_BINARY="$binary"
        export TEST_NGINX_BINARY
    fi
fi

"$here/init.sh"
exec "$here/start.sh" "$@"
