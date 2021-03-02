#!/bin/bash

i=0
curl_opt='-I'
url='http://localhost/'

# 循环次数不能太多，因为如果花费的时间超过一分钟 CC 计数会被重置，容易导致测试失败。
while [ $i -lt 200 ] ; do
    . test/get-http-status.sh
    ((i++))
done

. test/get-http-status.sh
if [ "$http_status" -ne 503 ] ; then
    exit 1
fi

