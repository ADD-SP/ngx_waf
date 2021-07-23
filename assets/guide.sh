#!/bin/sh

echo -n "checking for command ... "

which grep > /dev/null
if [ $? -ne 0 ] ; then
    echo 'no'
    echo "grep: command not found"
    exit 2
fi

which nginx > /dev/null
if [ $? -ne 0 ] ; then
    echo 'no'
    echo "nginx: command not found"
    exit 2
fi

echo "yes"


(nginx -V 2> /dev/stdout | grep "\-\-with-compat") > /dev/null

if [ $? -eq 0 ] ; then
    echo "It is recommended that you use dynamic modules."
else
    echo "It is recommended that you use static modules."
fi