#!/bin/bash

export http_status=$("curl -m 10 -o /dev/null -s -w %{http_code} ${curl_opt} ${url}")
