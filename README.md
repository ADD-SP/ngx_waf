# ngx_waf

<p align="center">
    <img src="https://cdn.jsdelivr.net/gh/ADD-SP/ngx_waf@master/logo.png" width=200 height=200/>
</p>

[![test](https://github.com/ADD-SP/ngx_waf/workflows/test/badge.svg)](https://github.com/ADD-SP/ngx_waf/actions?query=workflow%3Atest)
[![docs](https://github.com/ADD-SP/ngx_waf/actions/workflows/docs.yml/badge.svg)](https://docs.addesp.com/ngx_waf/)
[![docker](https://github.com/ADD-SP/ngx_waf/actions/workflows/docker.yml/badge.svg)](https://github.com/ADD-SP/ngx_waf/actions/workflows/docker.yml)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/aebcf93b4b7a4b4b800ceb962479ee3a?branch=master)](https://www.codacy.com/gh/ADD-SP/ngx_waf/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=ADD-SP/ngx_waf&amp;utm_campaign=Badge_Grade)
[![GitHub release (latest by date including pre-releases)](https://img.shields.io/github/v/release/ADD-SP/ngx_waf?include_prereleases)](https://github.com/ADD-SP/ngx_waf/releases)
[![Semantic Versioning 2.0.0](https://img.shields.io/badge/Semantic%20Versioning-2.0.0-blue)](https://semver.org/)

[![Notification](https://img.shields.io/badge/Notification-Telegram%20Channel-blue)](https://t.me/ngx_waf)
[![Chat](https://img.shields.io/badge/Discussion-Telegram%20Group-blue)](https://t.me/ngx_waf_group)

English | [简体中文](README-ZH-CN.md)

Handy, High performance Nginx firewall module.

## Why ngx_waf

* Full-featured: The basic functions of the web application firewall are available.
* Easy to install: The solution is automatically provided when a dependency is missing.
* Easy to use: directives are easy to understand and you can probably guess what they mean without reading the documentation.
* High performance: In more extreme tests, QPS(Queries Per Second) is reduced by about 4% after starting this module. See the documentation for details of the tests.

## Function

* Anti SQL injection (powered by [libinjection](https://github.com/libinjection/libinjection)).
* Anti XSS (powered by [libinjection](https://github.com/libinjection/libinjection)).
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

## Docs

* Recommended link: [https://docs.addesp.com/ngx_waf/](https://docs.addesp.com/ngx_waf/)
* Alternate link 1: [https://add-sp.github.io/ngx_waf/](https://add-sp.github.io/ngx_waf/)
* Alternate link 2: [https://ngx-waf.pages.dev/](https://ngx-waf.pages.dev/)

## Contact

* Telegram Channel: [https://t.me/ngx_waf](https://t.me/ngx_waf)
* Telegram Group: [https://t.me/ngx_waf_group](https://t.me/ngx_waf_group)

## License

[BSD 3-Clause License](LICENSE)

## Thanks

* [uthash](https://github.com/troydhanson/uthash): C macros for hash tables and more.
* [libinjection](https://github.com/libinjection/libinjection): SQL / SQLI tokenizer parser analyzer.
* [libsodium](https://github.com/jedisct1/libsodium): A modern, portable, easy to use crypto library.
* [lastversion](https://github.com/dvershinin/lastversion): A command line tool that helps you download or install a specific version of a project.
* [ngx_lua_waf](https://github.com/loveshell/ngx_lua_waf): A web application firewall based on the lua-nginx-module (openresty).
* [nginx-book](https://github.com/taobao/nginx-book): The Chinese language development guide for nginx.
* [nginx-development-guide](https://github.com/baishancloud/nginx-development-guide): The Chinese language development guide for nginx.
