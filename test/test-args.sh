#!/bin/bash

args=('test=base64_decode(test)')
curl_opt='-I'

for arg in $args ; do
    url="http://localhost?${arg}"
    echo "Testing arg: ${url}"
    . test/get-http-status.sh
    if [ "$http_status" -ne 403 ] ; then
        exit 1
    fi
done
