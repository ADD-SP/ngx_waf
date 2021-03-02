#!/bin/bash

urls=('www.bak')
curl_opt='-I'

for url in $urls ; do
    url="http://localhost/${url}"
    echo "Testing url: ${url}"
    . test/get-http-status.sh
    if [ "$http_status" -ne 403 ] ; then
        exit 1
    fi
done
