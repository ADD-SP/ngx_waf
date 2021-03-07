# ngx_waf

![ngx_waf](https://socialify.git.ci/ADD-SP/ngx_waf/image?description=1&descriptionEditable=%E7%94%A8%E4%BA%8E%20nginx%20%E7%9A%84%E6%B2%A1%E6%9C%89%E5%A4%8D%E6%9D%82%E9%85%8D%E7%BD%AE%E7%9A%84%20Web%20%E5%BA%94%E7%94%A8%E9%98%B2%E7%81%AB%E5%A2%99%E6%A8%A1%E5%9D%97%E3%80%82&language=1&owner=1&pattern=Brick%20Wall&theme=Light)

[![test](https://github.com/ADD-SP/ngx_waf/workflows/test/badge.svg)](https://github.com/ADD-SP/ngx_waf/actions?query=workflow%3Atest)
[![docs](https://github.com/ADD-SP/ngx_waf/actions/workflows/docs.yml/badge.svg)](https://docs.addesp.com/ngx_waf/zh-cn/)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/aebcf93b4b7a4b4b800ceb962479ee3a?branch=master)](https://www.codacy.com/gh/ADD-SP/ngx_waf/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=ADD-SP/ngx_waf&amp;utm_campaign=Badge_Grade)
[![GitHub release (latest by date including pre-releases)](https://img.shields.io/github/v/release/ADD-SP/ngx_waf?include_prereleases)](https://github.com/ADD-SP/ngx_waf/releases)
![GitHub](https://img.shields.io/github/license/ADD-SP/ngx_waf?color=blue)
[![语义化版本 2.0.0](https://img.shields.io/badge/%E8%AF%AD%E4%B9%89%E5%8C%96%E7%89%88%E6%9C%AC-2.0.0-blue)](https://semver.org/lang/zh-CN/)

[English](README.md) | 简体中文

一个用于 nginx 的没有复杂配置的 Web 应用防火墙模块。

## 功能

+ 支持 IPV4 和 IPV6。
+ CC 防御，超出限制后自动拉黑对应 IP 一段时间。
+ IP 黑白名单，同时支持类似 `192.168.0.0/16` 和 `fe80::/10`，即支持点分十进制和冒号十六进制表示法和网段划分。
+ POST 黑名单。
+ URL 黑白名单
+ GET 参数黑名单
+ UserAgent 黑名单。
+ Cookie 黑名单。
+ Referer 黑白名单。

## 使用文档

* 推荐链接：[https://docs.addesp.com/ngx_waf/zh-cn/](https://docs.addesp.com/ngx_waf/zh-cn/)
* 备用链接 1：[https://add-sp.github.io/ngx_waf/zh-cn/](https://add-sp.github.io/ngx_waf/zh-cn/)
* 备用链接 2：[https://ngx-waf.pages.dev/](https://ngx-waf.pages.dev/)

## 开源许可证

[BSD 3-Clause License](LICENSE)

## 感谢

+ [ngx_lua_waf](https://github.com/loveshell/ngx_lua_waf): 本模块的默认规则大多来自于此。
+ [nginx-book](https://github.com/taobao/nginx-book): 感谢作者提供的教程。
+ [nginx-development-guide](https://github.com/baishancloud/nginx-development-guide): 感谢作者提供的教程。
