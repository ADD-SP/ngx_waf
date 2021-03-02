# ngx_waf

![ngx_waf](https://socialify.git.ci/ADD-SP/ngx_waf/image?description=1&descriptionEditable=A%20web%20application%20firewall%20module%20for%20nginx%20without%20complex%20configuration.&language=1&owner=1&pattern=Brick%20Wall&theme=Light)

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/b34cd96389f941af8a9b7c4f7ffb6e14)](https://app.codacy.com/gh/ADD-SP/ngx_waf?utm_source=github.com&utm_medium=referral&utm_content=ADD-SP/ngx_waf&utm_campaign=Badge_Grade_Settings)
[![test](https://github.com/ADD-SP/ngx_waf/workflows/test/badge.svg)](https://github.com/ADD-SP/ngx_waf/actions?query=workflow%3Atest)
[![docs](https://github.com/ADD-SP/ngx_waf/actions/workflows/docs.yml/badge.svg)](https://add-sp.github.io/ngx_waf/)
[![](https://img.shields.io/badge/nginx-%3E%3D1.18.0-important)](http://nginx.org/en/download.html)
[![GitHub release (latest by date including pre-releases)](https://img.shields.io/github/v/release/ADD-SP/ngx_waf?include_prereleases)](https://github.com/ADD-SP/ngx_waf/releases)
![GitHub](https://img.shields.io/github/license/ADD-SP/ngx_waf?color=blue)
[![Discussions](https://img.shields.io/badge/Discussions-open-success)](https://github.com/ADD-SP/ngx_waf/discussions)
[![Semantic Versioning 2.0.0](https://img.shields.io/badge/Semantic%20Versioning-2.0.0-blue)](https://semver.org/)

English | [简体中文](README-ZH-CN.md)

A web application firewall module for nginx without complex configuration.

## Function

+ IPV4 and IPV6 support.
+ Anti Challenge Collapsar, it can automatically block malicious IP.
+ Exceptional allow on specific IP address.
+ Block the specified IP address.
+ Block the specified request body.
+ Exceptional allow on specific URL.
+ Block the specified URL.
+ Block the specified request args.
+ Block the specified UserAgent.
+ Block the specified Cookie.
+ Exceptional allow on specific Referer.
+ Block the specified Referer.

## Docs

[https://add-sp.github.io/ngx_waf/](https://add-sp.github.io/ngx_waf/)

## License

[BSD 3-Clause License](LICENSE)

## Thanks

+ [ngx_lua_waf](https://github.com/loveshell/ngx_lua_waf): Most of the default rules of this module come from this.
+ [nginx-book](https://github.com/taobao/nginx-book): Thanks for the tutorial provided by the author.
+ [nginx-development-guide](https://github.com/baishancloud/nginx-development-guide): Thanks for the tutorial provided by the author.
