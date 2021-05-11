# ngx_waf


<p align="center">
    <img src="https://raw.githubusercontent.com/ADD-SP/ngx_waf/master/logo.png" width=200 height=200/>
</p>


[![test](https://github.com/ADD-SP/ngx_waf/workflows/test/badge.svg)](https://github.com/ADD-SP/ngx_waf/actions?query=workflow%3Atest)
[![docs](https://github.com/ADD-SP/ngx_waf/actions/workflows/docs.yml/badge.svg)](https://docs.addesp.com/ngx_waf/zh-cn/)
[![docker](https://github.com/ADD-SP/ngx_waf/actions/workflows/docker.yml/badge.svg)](https://github.com/ADD-SP/ngx_waf/actions/workflows/docker.yml)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/aebcf93b4b7a4b4b800ceb962479ee3a?branch=master)](https://www.codacy.com/gh/ADD-SP/ngx_waf/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=ADD-SP/ngx_waf&amp;utm_campaign=Badge_Grade)
[![GitHub release (latest by date including pre-releases)](https://img.shields.io/github/v/release/ADD-SP/ngx_waf?include_prereleases)](https://github.com/ADD-SP/ngx_waf/releases)
[![语义化版本 2.0.0](https://img.shields.io/badge/%E8%AF%AD%E4%B9%89%E5%8C%96%E7%89%88%E6%9C%AC-2.0.0-blue)](https://semver.org/lang/zh-CN/)

[![Notification](https://img.shields.io/badge/Notification-Telegram%20Channel-blue)](https://t.me/ngx_waf)
[![Chat](https://img.shields.io/badge/Chat-Telegram%20Group-blue)](https://t.me/ngx_waf_group)

[English](README.md) | 简体中文

方便且高性能的 Nginx 防火墙模块。

## 为什么选择 ngx_waf

* 功能齐全：「网络应用防火墙」的基本功能都有。
* 安装方便：无需提前安装其它模块。
* 使用方便：配置指令简单易懂，不用看文档都能猜到大概是什么意思。
* 高性能：经过较为极限的测试，启动本模块后 RPS（每秒请求数） 降低约 4%。测试说明和结果见使用文档。

## 功能

* SQL 注入检测。
* 支持 IPV4 和 IPV6。
* CC 防御，超出限制后自动拉黑对应 IP 一段时间。
* IP 黑白名单，同时支持类似 `192.168.0.0/16` 和 `fe80::/10`，即支持点分十进制和冒号十六进制表示法和网段划分。
* POST 黑名单。
* URL 黑白名单
* 查询字符串（Query String）黑名单。
* UserAgent 黑名单。
* Cookie 黑名单。
* Referer 黑白名单。

## 使用文档

* 推荐链接：[https://docs.addesp.com/ngx_waf/zh-cn/](https://docs.addesp.com/ngx_waf/zh-cn/)
* 备用链接 1：[https://add-sp.github.io/ngx_waf/zh-cn/](https://add-sp.github.io/ngx_waf/zh-cn/)
* 备用链接 2：[https://ngx-waf.pages.dev/zh-cn/](https://ngx-waf.pages.dev/zh-cn/)

## 联系方式

* Telegram 频道: [https://t.me/ngx_waf](https://t.me/ngx_waf)
* Telegram 群组: [https://t.me/ngx_waf_group](https://t.me/ngx_waf_group)

## 开源许可证

[BSD 3-Clause License](LICENSE)

## 感谢

* [uthash](https://github.com/troydhanson/uthash)
* [libinjection](https://github.com/client9/libinjection)
* [libsodium](https://github.com/jedisct1/libsodium)
* [ngx_lua_waf](https://github.com/loveshell/ngx_lua_waf)
* [nginx-book](https://github.com/taobao/nginx-book)
* [nginx-development-guide](https://github.com/baishancloud/nginx-development-guide)
