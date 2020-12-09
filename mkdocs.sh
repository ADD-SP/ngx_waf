#!/bin/bash

if [ -d docs/ZH-CN/html ] ; then
    rm -rf docs/ZH-CN/html
fi

# mkdir -p doc/EN

doxygen doxygen-ZH-CN.conf