#!/bin/sh

export PATH=/usr/local/openresty/nginx/sbin:$PATH

if [ -e "/usr/local/nginx/modules/ngx_http_waf_module.so" ] ; then
    export TEST_NGINX_LOAD_MODULES=/usr/local/nginx/modules/ngx_http_waf_module.so
fi

# export TEST_NGINX_LOG_LEVEL=emerg
# export TEST_NGINX_SLEEP=1
# export TEST_NGINX_NO_CLEAN=1
# export TEST_NGINX_MASTER_PROCESS=on

exec prove "$@"