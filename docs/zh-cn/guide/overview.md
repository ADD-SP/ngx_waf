---
title: 简介
lang: zh-CN
---

# 简介

方便又高性能的 Nginx 防火墙模块。

## 为什么选择 ngx_waf

* 功能齐全：「网络应用防火墙」的基本功能都有。
* 安装方便：大多数情况下你可以直接下载使用预构建的模块，而不是编译代码。
* 使用方便：配置指令简单易懂，不用看文档都能猜到大概是什么意思。
* 规则灵活：提供高级规则，将动作（如拦截或放行）和多个条件表达式组合起来。
* 高性能：经过较为极限的测试，启动本模块后 RPS（每秒请求数） 降低约 4%。测试说明和结果见使用文档。

## 功能

* SQL 注入防护（Powered By [libinjection](https://github.com/libinjection/libinjection)）。
* XSS 攻击防护（Powered By [libinjection](https://github.com/libinjection/libinjection)）。
* 支持 IPV4 和 IPV6。
* CC 防御，超出限制后自动拉黑对应 IP 一段时间。
* IP 黑白名单，同时支持类似 `192.168.0.0/16` 和 `fe80::/10`，即支持点分十进制和冒号十六进制表示法和网段划分。
* POST 黑名单。
* URL 黑白名单
* 查询字符串（Query String）黑名单。
* UserAgent 黑名单。
* Cookie 黑名单。
* Referer 黑白名单。
* 高级规则，将动作（如拦截或放行）和多个条件表达式组合起来。

## 联系方式

* Telegram 频道: [https://t.me/ngx_waf](https://t.me/ngx_waf)
* Telegram 群组（英文）: [https://t.me/group_ngx_waf](https://t.me/group_ngx_waf)
* Telegram 群主（中文）：[https://t.me/group_ngx_waf_cn](https://t.me/group_ngx_waf_cn)

## 性能测试

[性能测试](test.md#性能测试)

## 闲谈

[nginx 防火墙模块开发总结](https://www.addesp.com/archives/2876)

欢迎访问我的博客：[https://www.addesp.com/](https://www.addesp.com/)。

## 感谢

* [uthash](https://github.com/troydhanson/uthash)：C 语言的哈希表、数组、链表等容器库。
* [libinjection](https://github.com/libinjection/libinjection)：SQL 注入检测库。
* [libsodium](https://github.com/jedisct1/libsodium)：C 语言密码函数库。
* [lastversion](https://github.com/dvershinin/lastversion)：一个轻巧的命令行工具，帮助你下载或安装一个项目的特定版本。
* [ngx_lua_waf](https://github.com/loveshell/ngx_lua_waf)：一个基于 lua-nginx-module (openresty) 的 web 应用防火墙。 
* [nginx-book](https://github.com/taobao/nginx-book)：Nginx开发从入门到精通 
* [nginx-development-guide](https://github.com/baishancloud/nginx-development-guide)：Nginx 开发指南。

