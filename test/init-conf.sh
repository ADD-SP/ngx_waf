#!/bin/bash

ngx_root=$1
new_static_module_conf='test/nginx-static-module.conf'
new_dynamic_module_conf='test/nginx-dynamic-module.conf'
rules_dir='assets/rules'

if [ -e "${ngx_root}/conf/nginx.conf" ] ; then
    rm -rf "${ngx_root}/conf/nginx.conf"
fi

if [ "$opt" = '--add-module' ] ; then
    cp "${new_static_module_conf}" "${ngx_root}/conf/nginx.conf"
else
    cp "${new_dynamic_module_conf}" "${ngx_root}/conf/nginx.conf"
fi

cp -r "${rules_dir}" "${ngx_root}/conf/rules"
