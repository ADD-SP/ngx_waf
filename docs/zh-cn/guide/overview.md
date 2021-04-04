---
title: 简介
lang: zh-CN
---

# 简介

一个用于 nginx 的没有复杂配置的 Web 应用防火墙模块。

::: danger 重大缺陷

当 nginx 的 worker 进程数量大于一时，当前稳定版的模块会出现段错误。请使用最新的开发版。

:::

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

## 闲谈

[nginx 防火墙模块开发总结](https://www.addesp.com/archives/2876)

欢迎访问我的博客：[https://www.addesp.com/](https://www.addesp.com/)。

