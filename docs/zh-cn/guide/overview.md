---
title: 简介
lang: zh-CN
---

# 简介

方便又高性能的 Nginx 防火墙模块。

## 为什么选择 ngx_waf

* 功能齐全：「网络应用防火墙」的基本功能都有。
* 安装方便：
    * 仅依赖 `uthash` 库，并且可以直接通过包管理器（如 apt）安装。
    * 无需提前安装其它模块。
* 使用方便：配置指令简单易懂，不用看文档都能猜到大概是什么意思。
* 高性能：经过较为极限的测试，启动本模块后 RPS（每秒请求数） 降低约 4%。测试说明和结果见使用文档。

## 功能

* 支持 IPV4 和 IPV6。
* CC 防御，超出限制后自动拉黑对应 IP 一段时间。
* IP 黑白名单，同时支持类似 `192.168.0.0/16` 和 `fe80::/10`，即支持点分十进制和冒号十六进制表示法和网段划分。
* POST 黑名单。
* URL 黑白名单
* 查询字符串（Query String）黑名单。
* UserAgent 黑名单。
* Cookie 黑名单。
* Referer 黑白名单。

## 联系方式

* Telegram 频道: [https://t.me/ngx_waf](https://t.me/ngx_waf)
* Telegram 群组: [https://t.me/ngx_waf_group](https://t.me/ngx_waf_group)

## 性能测试

[性能测试](test.md#性能测试)

## 闲谈

[nginx 防火墙模块开发总结](https://www.addesp.com/archives/2876)

欢迎访问我的博客：[https://www.addesp.com/](https://www.addesp.com/)。

