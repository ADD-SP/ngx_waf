#!/bin/bash

cookies=('test=base64_decode(test)&aaa=12&bbb=13&ccc=14')
url="http://localhost/"

for cookie in $cookies ; do
    curl_opt="-b '${cookie}'"
    echo "Testing cookie: ${cookie}"
    . test/get-http-status.sh
    if [ "$http_status" -ne 403 ] ; then
        exit 1
    fi
done
