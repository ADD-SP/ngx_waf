#!/bin/sh
# Run the nginx integration suite against the built module.
#
# `MODULE_PATH` selects the dynamic module to load, without it the tests
# expect a nginx built with the static module.

set -e

here=$(cd "$(dirname "$0")" && pwd)

# The fixtures are removed again when this script made the directory: a caller
# that names it (`MODULE_TEST_PATH=/tmp/waf-test-path ./run.sh`) keeps them,
# which is what looking into a failure wants.
module_test_path_created=0

if [ -z "$MODULE_TEST_PATH" ]; then
    MODULE_TEST_PATH=$(mktemp -d)
    module_test_path_created=1
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

# The suite runs without `exec` so the fixtures can be removed and its exit
# status survives, one of the tests failing has to stay visible to the caller.
set +e
"$here/start.sh" "$@"
status=$?
set -e

if [ "$module_test_path_created" = 1 ]; then
    rm -rf "$MODULE_TEST_PATH"
fi

exit "$status"
