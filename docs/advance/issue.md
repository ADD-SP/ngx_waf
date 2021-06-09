---
title: Known Issues
lang: en
---

# Known Issues

Bugs that exist in the latest stable release are listed here, 
bugs that have been fixed in the latest stable release are not listed here.

## POST requests are not logged in the access log

* Overview: When POST inspection is enabled, POST requests are not logged in the access log.
* Severity: Low.
* Priority: It will be fixed in the next stable release.
* Status: Already fixed in the latest beta release.
* Affected versions:
    * nginx: >= `1.18.0`.
    * ngx_waf: >= `1.0.0`.