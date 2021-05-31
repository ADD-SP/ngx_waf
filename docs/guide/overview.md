---
title: Overview
lang: en
---

# Overview

Handy, High performance Nginx firewall module.

## Why ngx_waf

* Full-featured: The basic functions of the web application firewall are available.
* Easy to install. The solution is automatically provided when a dependency is missing.
* Easy to use: directives are easy to understand and you can probably guess what they mean without reading the documentation.
* High performance: In more extreme tests, QPS (Queries Per Second) is reduced by about 4% after starting this module. See the documentation for details of the tests.

## Function

* Anti SQL injection (powered by [libinjection](https://github.com/client9/libinjection)).
* Anti XSS (powered by [libinjection](https://github.com/client9/libinjection)).
* IPV4 and IPV6 support.
* Anti Challenge Collapsar, it can automatically block malicious IP.
* Exceptional allow on specific IP address.
* Block the specified IP address.
* Block the specified request body.
* Exceptional allow on specific URL.
* Block the specified URL.
* Block the specified query string.
* Block the specified UserAgent.
* Block the specified Cookie.
* Exceptional allow on specific Referer.
* Block the specified Referer.


::: tip NOTE

The feature `Anti XSSS` is currently only available in the development version.

:::

## Contact

* Telegram Channel: [https://t.me/ngx_waf](https://t.me/ngx_waf)
* Telegram Group: [https://t.me/ngx_waf_group](https://t.me/ngx_waf_group)

## Performance Test

[Performance Test](test.md#performance-test)
