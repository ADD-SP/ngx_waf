#!/bin/sh

if [ "$1" != stable -a "$1" != mainline ] ; then
    echo "$1: invalid argument"
    exit 22
fi

if [ "$2" != stable -a "$2" != beta ] ; then
    echo "$1: invalid argument"
    exit 22
fi

echo -n "checking for command ... "

which find > /dev/null
if [ $? -ne 0 ] ; then
    echo 'no'
    echo "find: command not found"
    exit 2
fi

which grep > /dev/null
if [ $? -ne 0 ] ; then
    echo 'no'
    echo "grep: command not found"
    exit 2
fi

which docker > /dev/null
if [ $? -ne 0 ] ; then
    echo 'no'
    echo "docker: command not found"
    exit 2
fi

echo 'yes'

echo -n "checking for libc implementation ... "

tmp=`find -L /lib* -regex \.*libc\.so.*` 2> /dev/null

echo "$tmp" | grep gnu > /dev/null
if [ $? -eq 0 ] ; then
    echo 'yes'
    echo ' + GNU C libary'
else
    echo "$tmp" | grep musl > /dev/null
    if [ $? -eq 0 ] ; then
        echo 'yes'
        echo ' + musl C libary'
    else
        echo 'no'
        exit 2
    fi
fi

echo -n "pulling remote image addsp/ngx_waf-prebuild:ngx-$1-module-$2 ... "
tmp=`docker pull "addsp/ngx_waf-prebuild:ngx-$1-module-$2"` 2> /dev/null
if [ $? -ne 0 ] ; then
    echo 'no'
    exit 121
else
    echo 'yes'
fi


tmpdir=`head -10 /dev/urandom | md5sum - | cut -c 1-32`
while [ -e $(pwd)/tmpdir ]
do
    tmpdir=`head -10 /dev/urandom | md5sum - | cut -c 1-32`
done

tmp=`docker run --rm -d -v "$(pwd)/$tmpdir":/out "addsp/ngx_waf-prebuild:ngx-$1-module-$2" cp /modules/ngx_http_waf_module.so /out` 2> /dev/null

cp "$(pwd)/$tmpdir/ngx_http_waf_module.so" ./
rm -rf "$(pwd)/$tmpdir"