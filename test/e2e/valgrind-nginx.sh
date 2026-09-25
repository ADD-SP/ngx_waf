#!/bin/sh
# Run the nginx binary of the tree under valgrind, for `mise run test-valgrind`.
#
# The Test::Nginx templates are wrapped by `TEST_NGINX_USE_VALGRIND`; the end
# to end script walks its own nginx process, so it is handed this wrapper as
# `NGINX_BIN` and the real binary in `NGX_WAF_NGINX` instead.

set -eu

here=$(cd "$(dirname "$0")" && pwd)
nginx="${NGX_WAF_NGINX:?NGX_WAF_NGINX is not set}"
suppress="${VALGRIND_SUPPRESS:-$here/../test-nginx/valgrind.suppress}"

exec valgrind -q \
    --tool=memcheck \
    --leak-check=full \
    --show-possibly-lost=no \
    --num-callers=100 \
    --gen-suppressions=all \
    --suppressions="$suppress" \
    "$nginx" "$@"
