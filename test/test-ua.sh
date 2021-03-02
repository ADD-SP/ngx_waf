#!/bin/bash

user_agents=('bench')
url="http://localhost/"

for user_agent in $user_agents ; do
    curl_opt="-A '${user_agent}'"
    echo "Testing User-Agent: ${user_agent}"
    . test/get-http-status.sh
    if [ "$http_status" -ne 403 ] ; then
        exit 1
    fi
done
