#!/bin/python3

import os
import re
import sys
import subprocess


output = subprocess.getstatusoutput("nginx -V")[1]

lines = output.split("\n")

raw_arguments = ""

for line in lines:
    if line.startswith("configure arguments:"):
        raw_arguments = line.split(":")[1]
        break

extra_cc_opt = re.search(r"--with-cc-opt='(.+?)'", raw_arguments).group(1)
extra_ld_opt = re.search(r"--with-ld-opt='(.+?)'", raw_arguments)
if extra_ld_opt == None:
    extra_ld_opt = re.search(r"--with-ld-opt=([^\s]+)", raw_arguments)

extra_ld_opt = extra_ld_opt.group(1)

if sys.argv[1] == "OUTPUT_ARGUMENTS":
    arguments = raw_arguments.replace(extra_cc_opt, "${EXTRA_CFLAGS}")
    arguments = arguments.replace(extra_ld_opt, "${EXTRA_LFLAGS}")
    arguments = arguments.replace("\'", "")
    print(arguments)
elif sys.argv[1] == "OUTPUT_EXTRA_CFLAGS":
    print(extra_cc_opt)
elif sys.argv[1] == "OUTPUT_EXTRA_LFLAGS":
    print(extra_ld_opt)