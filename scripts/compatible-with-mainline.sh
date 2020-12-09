#!/bin/bash

if [ -n $NGX_WAF_COMPATIBLE_WITH_MAINLINE -o $NGX_WAF_COMPATIBLE_WITH_MAINLINE = 'TRUE' ] ; then
    sed -i '/#define NGX_HTTP_WAF_MODULE_CONFIG_H/a\#define COMPATIBLE_WITH_MAINLINE' inc/ngx_http_waf_module_config.h
fi

