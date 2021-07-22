#!/bin/sh

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

imp=''

tmp=`find -L /lib* -regex \.*libc\.so.* 2> /dev/null`

echo "$tmp" | grep gnu > /dev/null
if [ $? -eq 0 ] ; then
    echo 'yes'
    imp='glibc'
    echo ' + GNU C libary'
else
    echo "$tmp" | grep musl > /dev/null
    if [ $? -eq 0 ] ; then
        echo 'yes'
        imp='musl'
        echo ' + musl C libary'
    fi
fi

if [ -z "$imp" ] ; then 
    which ldd > /dev/null
    if [ $? -ne 0 ] ; then
        echo 'no'
        echo "ldd: command not found"
        exit 2
    else
        tmp=`ldd --version`
        echo "$tmp" | grep -E -e "(.*GNU.*)|(.*GLIBC.*)" > /dev/null
        if [ $? -eq 0 ] ; then
            echo 'yes'
            imp='glibc'
            echo ' + GNU C libary'
        else
            echo "$tmp" | grep -E -e "(.*musl.*)" > /dev/null
            if [ $? -eq 0 ] ; then
                echo 'yes'
                imp='musl'
                echo ' + musl C libary'
            else
                echo 'no'
                exit 2
            fi
        fi
    fi
fi


echo "Pulling remote image addsp/ngx_waf-prebuild:ngx-$1-module-$2-$imp"
docker pull "addsp/ngx_waf-prebuild:ngx-$1-module-$2-$imp"
if [ $? -eq 0 ] ; then
    tmpdir=`head -10 /dev/urandom | md5sum - | cut -c 1-32`
    while [ -e $(pwd)/tmpdir ]
    do
        tmpdir=`head -10 /dev/urandom | md5sum - | cut -c 1-32`
    done

    docker run --rm -d -v "$(pwd)/$tmpdir":/out "addsp/ngx_waf-prebuild:ngx-$1-module-$2-$imp" cp /modules/ngx_http_waf_module.so /out

    cp "$(pwd)/$tmpdir/ngx_http_waf_module.so" ./
    rm -rf "$(pwd)/$tmpdir"

    echo "Download complete!"
fi


