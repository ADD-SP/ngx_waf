---
title: Limit the rate per arbitrary URL
lang: en
---

# Limit the rate per arbitrary URL

## Overview

Sometimes you may want to limit the request rate for different paths or files, such as using different rate limits for static and dynamic resources.

## Configuration

```nginx
# Limit the request rate for static resources to 10,000 requests per minute.
location /static/ {
    waf_cc_deny rate=10000r/m duration=1h;
}

# Limit the request rate for dynamic resources to 2,000 requests per minute.
location /dynamic/ {
    waf_cc_deny rate=2000r/m duration=1h;
}
```

