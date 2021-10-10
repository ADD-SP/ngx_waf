# ngx_waf


<p align="center">
    <img src="https://cdn.jsdelivr.net/gh/ADD-SP/ngx_waf@master/assets/logo.png" width=200 height=200/>
</p>


[![test](https://github.com/ADD-SP/ngx_waf/workflows/test/badge.svg)](https://github.com/ADD-SP/ngx_waf/actions?query=workflow%3Atest)
[![docs](https://github.com/ADD-SP/ngx_waf-docs/actions/workflows/docs.yml/badge.svg)](https://docs.addesp.com/ngx_waf/zh-cn/)
[![docker](https://github.com/ADD-SP/ngx_waf/actions/workflows/docker.yml/badge.svg)](https://hub.docker.com/r/addsp/ngx_waf-prebuild)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/aebcf93b4b7a4b4b800ceb962479ee3a?branch=master)](https://www.codacy.com/gh/ADD-SP/ngx_waf/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=ADD-SP/ngx_waf&amp;utm_campaign=Badge_Grade)
[![Codacy Badge](https://app.codacy.com/project/badge/Coverage/aebcf93b4b7a4b4b800ceb962479ee3a?branch=master)](https://www.codacy.com/gh/ADD-SP/ngx_waf/dashboard?utm_source=github.com&utm_medium=referral&utm_content=ADD-SP/ngx_waf&utm_campaign=Badge_Coverage)

[![Notification](https://img.shields.io/badge/Notification-Telegram%20Channel-blue)](https://t.me/ngx_waf)
[![Discussion EN](https://img.shields.io/badge/Discussion%20EN-Telegram%20Group-blue)](https://t.me/group_ngx_waf)
[![Discussion CN](https://img.shields.io/badge/Discussion%20CN-Telegram%20Group-blue)](https://t.me/group_ngx_waf_cn)

[English](README.md) | 简体中文

方便且高性能的 Nginx 防火墙模块。

## 为什么选择 ngx_waf

* 基础防护：如 IP 或 IP 网段的黑白名单、URI 黑白名单和请求体黑名单等。
* 使用简单：配置文件和规则文件书写简单，可读性强。
* 高性能：使用高效的 IP 检查算法和缓存机制。
* 高级防护：兼容 [ModSecurity](https://github.com/SpiderLabs/ModSecurity)，因此你可以使用[开放式网络应用安全项目（OWASP）® 的核心规则库](https://owasp.org/www-project-modsecurity-core-rule-set/)。
* 友好爬虫验证：支持验证 Google、Bing、Baidu 和 Yandex 的爬虫并自动放行，避免错误拦截。
* 验证码：支持三种验证码：hCaptcha、reCAPTCHAv2 和 reCAPTCHAv3。

## 功能

* 兼容 [ModSecurity](https://github.com/SpiderLabs/ModSecurity)。此功能仅限最新的 Current 版本。
* SQL 注入防护（Powered By [libinjection](https://github.com/libinjection/libinjection)）。
* XSS 攻击防护（Powered By [libinjection](https://github.com/libinjection/libinjection)）。
* 支持 IPV4 和 IPV6。
* 支持开启验证码（CAPTCHA)，支持 [hCaptcha](https://www.hcaptcha.com/)、[reCAPTCHAv2](https://developers.google.com/recaptcha) 和 [reCAPTCHAv3](https://developers.google.com/recaptcha)。此功能仅限最新的 Current 版本。
* 支持识别友好爬虫（如 BaiduSpider）并自动放行（基于 User-Agent 和 IP 的识别）。此功能仅限最新的 Current 版本。
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
* 备用链接 1：[https://add-sp.github.io/ngx_waf-docs/zh-cn/](https://add-sp.github.io/ngx_waf-docs/zh-cn/)
* 备用链接 2：[https://ngx-waf-docs.pages.dev/zh-cn/](https://ngx-waf-docs.pages.dev/zh-cn/)

## 联系方式

* Telegram 频道: [https://t.me/ngx_waf](https://t.me/ngx_waf)
* Telegram 群组（英文）: [https://t.me/group_ngx_waf](https://t.me/group_ngx_waf)
* Telegram 群组（中文）：[https://t.me/group_ngx_waf_cn](https://t.me/group_ngx_waf_cn)

## 打赏

打赏就算了，如果您愿意，您可以帮助宣传一下本项目。比如发个贴，推荐给身边有需求的人什么的。

<del>我从来没碰过钱，我对钱没有兴趣。</del>

## 测试套件

本项目使用一个 Perl 开发的数据驱动型的测试套件进行测试。
感谢项目 [Test::Nginx](http://search.cpan.org/perldoc?Test::Nginx) 及其开发者们。

你可以通过下列命令来运行测试。

```shell
# 这行命令的执行时间比较长，但是以后再测试的时候就不需要运行了。
cpan Test::Nginx

# 你需要指定一个临时目录。
# 如果目录不存在会自动创建。
# 如果目录已经会被存在则会先**删除**再创建。
export MODULE_TEST_PATH=/path/to/temp/dir

# 如果你安装了动态模块则需要指定动态模块的绝对路径，反之则无需执行这行命令。
export MODULE_PATH=/path/to/ngx_http_waf_module.so

cd ./test/test-nginx
sh ./init.sh
sh ./start.sh ./t/*.t
```


## 开源许可证

[BSD 3-Clause License](LICENSE)

## 感谢

* [ModSecurity](https://github.com/SpiderLabs/ModSecurity)：开源且跨平台的 WAF 引擎。
* [uthash](https://github.com/troydhanson/uthash)：C 语言的哈希表、数组、链表等容器库。
* [libcurl](https://curl.se/libcurl/)：支持多种协议文件传输库。
* [cJSON](https://github.com/DaveGamble/cJSON)：C 语言的轻量级 JSON 解析库。
* [libinjection](https://github.com/libinjection/libinjection)：SQL 注入检测库。
* [libsodium](https://github.com/jedisct1/libsodium)：C 语言密码函数库。
* [test-nginx](https://github.com/openresty/test-nginx): 数据驱动的 nginx 测试套件，可用于 nginx C 模块的开发和 OpenResty Lua 库的开发。 
* [lastversion](https://github.com/dvershinin/lastversion)：一个轻巧的命令行工具，帮助你下载或安装一个项目的特定版本。
* [ngx_lua_waf](https://github.com/loveshell/ngx_lua_waf)：一个基于 lua-nginx-module (openresty) 的 web 应用防火墙。
* [nginx-book](https://github.com/taobao/nginx-book)：Nginx开发从入门到精通 
* [nginx-development-guide](https://github.com/baishancloud/nginx-development-guide)：Nginx 开发指南。
