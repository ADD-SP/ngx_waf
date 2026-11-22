# ngx_waf


<p align="center">
    <img src="https://cdn.jsdelivr.net/gh/ADD-SP/ngx_waf@master/assets/logo.png" width=200 height=200/>
</p>


[![test](https://github.com/ADD-SP/ngx_waf/workflows/test/badge.svg)](https://github.com/ADD-SP/ngx_waf/actions?query=workflow%3Atest)
[![docs](https://github.com/ADD-SP/ngx_waf-docs/actions/workflows/docs.yml/badge.svg)](https://add-sp.github.io/ngx_waf-docs/zh-cn/)

[![Notification](https://img.shields.io/badge/Notification-Telegram%20Channel-blue)](https://t.me/ngx_waf)
[![Discussion EN](https://img.shields.io/badge/Discussion%20EN-Telegram%20Group-blue)](https://t.me/group_ngx_waf)
[![Discussion CN](https://img.shields.io/badge/Discussion%20CN-Telegram%20Group-blue)](https://t.me/group_ngx_waf_cn)

[English](README.md) | 简体中文

方便且高性能的 Nginx 防火墙模块。

## 为什么选择 ngx_waf

* 规则统一：[ModSecurity](https://github.com/SpiderLabs/ModSecurity) 是唯一的请求规则引擎，可直接加载[开放式网络应用安全项目（OWASP）® 的核心规则库](https://owasp.org/www-project-modsecurity-core-rule-set/)。
* 状态化防护：内置 CC、CAPTCHA、Under Attack 和友好爬虫验证，不把这些流程与正则规则混在一起。
* 友好爬虫验证：支持验证 Google、Bing、Baidu 和 Yandex 的爬虫并自动放行，避免错误拦截。
* 验证码：支持 hCaptcha、Cloudflare Turnstile、reCAPTCHAv2 和 reCAPTCHAv3。

## 功能

* [ModSecurity](https://github.com/SpiderLabs/ModSecurity) 是唯一的请求匹配与阻断规则引擎；IP、URL、Header、参数和 Body 规则均使用 SecRule。
* `waf_priority` 可在 `VERIFY-BOT`、`CC`、`CAPTCHA`、`UNDER-ATTACK`、`MODSECURITY` 五项之间调整顺序。
* 支持开启验证码（CAPTCHA)，支持 [hCaptcha](https://www.hcaptcha.com/)、[Cloudflare Turnstile](https://developers.cloudflare.com/turnstile/)、[reCAPTCHAv2](https://developers.google.com/recaptcha) 和 [reCAPTCHAv3](https://developers.google.com/recaptcha)。
* 支持识别友好爬虫（如 BaiduSpider）并自动放行（基于 User-Agent 和 IP 的识别）。
* CC 防御，超出限制后自动拉黑对应 IP 一段时间或者使用验证码做人机识别。
* Under Attack 五秒等待页。

不再提供 `waf_rule_path`、`waf_mode`、`waf_cache` 或原生 black/white 规则文件。
`waf_modsecurity on` 必须至少提供一个 `file=`，或者成对的
`remote_key=` 与 `remote_url=`。

```nginx
waf on;
waf_modsecurity on file=/etc/nginx/modsec/main.conf;
waf_priority "VERIFY-BOT CC CAPTCHA UNDER-ATTACK MODSECURITY";
```

## 使用文档

* 推荐链接：[https://add-sp.github.io/ngx_waf-docs/zh-cn/](https://add-sp.github.io/ngx_waf-docs/zh-cn/)
* 备用链接：[https://ngx-waf-docs.pages.dev/zh-cn/](https://ngx-waf-docs.pages.dev/zh-cn/)

## 从源码构建

模块由一层很薄的 C 胶水代码和一个承载全部逻辑的 Rust 核心组成（见
[`rust/README.md`](rust/README.md)），不再使用 Bazel。

构建任务与 Debian/Ubuntu 系统依赖声明在 [`mise.toml`](mise.toml) 中，用
[mise](https://mise.jdx.dev) 执行。Rust 工具链不由 mise 管理：仍由 rustup 与
`rust-toolchain.toml` 固定，因此请先安装 rustup。

```sh
mise trust         # 允许 mise 读取 mise.toml
mise bootstrap -y  # 安装系统依赖与固定版本的 cbindgen
mise run build     # 在 test/nginx-<version> 中构建带静态模块的 nginx
mise run test      # Rust 单元测试与 nginx 集成测试
mise run test-e2e  # 自研端到端检查，单 worker 与四 worker 各跑一轮
mise run coverage  # Rust 单元测试的覆盖率，每个模块一行
mise run test-valgrind  # 在 valgrind 下跑模板套件与端到端检查
```

`mise run doctor` 检查 cargo、rustc 与 cbindgen 是否在 PATH 上。需要 stable
Rust 工具链（含 cargo）以及 libmodsecurity 3 的开发文件（例如
`libmodsecurity-dev` 软件包，或用 `LIB_MODSECURITY` 指定安装前缀），并且 nginx
必须启用 SSL 支持（`--with-http_ssl_module`）：访问验证码服务商的客户端使用的
是 nginx 自身的 TLS 设施。`[bootstrap.packages]` 只列 Debian/Ubuntu 的软件包，
其他发行版请用其包管理器安装等价依赖（C 工具链、zlib、PCRE2、OpenSSL、
libmodsecurity 3、perl）。`NGINX_SRC` 指定要复制的 nginx 源码目录，
`NGINX_VERSION` 指定缺失时下载的版本，`mise run build-dynamic` 构建动态模块。
与 C 实现的已知差异见 [`rust/README.md`](rust/README.md)。

`mise run coverage` 打印单元测试的覆盖率，每个模块一行，并排除源码里
`mod tests` 块中的测试代码。`mise run coverage-e2e` 更进一步：构建插桩的
nginx，在其上运行自研端到端检查与 Test::Nginx 套件，并打印两次运行的并集。
两个任务都需要工具链的 `llvm-tools-preview` 组件（缺失时任务会提示执行
`rustup component add llvm-tools-preview`）。

`mise run test-valgrind` 在 valgrind 下运行 Test::Nginx 模板与自研端到端检查，
一旦 valgrind 报告任何内容就判失败；nginx 自身与 libmodsecurity 里 PCRE2 JIT
的记录由 `test/test-nginx/valgrind.suppress` 抑制。请先安装 valgrind
（Debian/Ubuntu：`apt-get install valgrind`）；传入模板名可只跑指定文件
（`mise run test-valgrind t/captcha.t`）。CI 在 stable 分支的静态模块组合上
运行它。

## 联系方式

* Telegram 频道: [https://t.me/ngx_waf](https://t.me/ngx_waf)
* Telegram 群组（英文）: [https://t.me/group_ngx_waf](https://t.me/group_ngx_waf)
* Telegram 群组（中文）：[https://t.me/group_ngx_waf_cn](https://t.me/group_ngx_waf_cn)

## 打赏

打赏就算了，如果您愿意，您可以帮助宣传一下本项目。比如发个贴，推荐给身边有需求的人什么的。

<del>我从来没碰过钱，我对钱没有兴趣。</del>

## 测试套件

本项目使用一个 Perl 开发的数据驱动型的测试套件进行测试。
感谢项目 [Test::Nginx](https://metacpan.org/pod/Test::Nginx) 及其开发者们。

先在机器上装好依赖并构建套件要运行的 nginx，然后运行全部模板：

```shell
# 系统依赖里包含 cpanminus；第二行安装 Test::Nginx。
mise bootstrap -y
mise run test-nginx-deps

mise run build           # 或：mise run build-dynamic

mise run test-nginx
```

`mise run test-nginx` 运行全部模板；传入一个或多个测试文件则只跑这些：

```shell
mise run test-nginx t/modsecurity.t
```

动态构建时导出 `MODULE_PATH=/path/to/ngx_http_waf_module.so`；需要测试
`mise run build` 之外的其他 nginx 二进制时导出
`TEST_NGINX_BINARY=/path/to/nginx`。

部分模板会访问真实的验证码服务商，因此测试需要网络。

## 开源许可证

[BSD 3-Clause License](LICENSE)

## 感谢

* [ModSecurity](https://github.com/SpiderLabs/ModSecurity)：开源且跨平台的 WAF 引擎。
* [test-nginx](https://github.com/openresty/test-nginx): 数据驱动的 nginx 测试套件，可用于 nginx C 模块的开发和 OpenResty Lua 库的开发。 
* [ngx_lua_waf](https://github.com/loveshell/ngx_lua_waf)：一个基于 lua-nginx-module (openresty) 的 web 应用防火墙。
