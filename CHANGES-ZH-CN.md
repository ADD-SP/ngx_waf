## Unreleased

* 模块逻辑正在用 Rust 重写：C 代码只保留 nginx 胶水层（模块与指令注册、请求数据
  打包、响应与变量落地），其余逻辑位于 `rust/`。
* 使用 nginx `config` 脚本、cargo 与 mise 任务取代 Bazel。
* FFI 头文件 `include/ngx_http_waf_ffi.h` 由 cbindgen 生成并入库。
* 构建入口从根 `Makefile` 迁移到 mise 任务（`.mise/tasks/`，`mise run <task>`）。
  `mise.toml` 还声明了固定版本的 cbindgen 与 Debian/Ubuntu 系统依赖；Rust 工具链
  仍由 rustup 与 `rust-toolchain.toml` 提供。
* C ABI 只保留边界本身的词汇：step、事件、请求方法与协议版本的枚举，配置与
  请求检测的不透明句柄，以及语义化的配置查询。实现的常量与内部类型不再跨边界。
* 所有检测项均已移植，包括异步部分：验证码与友好爬虫校验通过 nginx 的
  resolver 做反向解析、通过与验证码服务商的非阻塞请求完成验证。
  服务商响应的 HTTP 报文框架由核心解析，胶水层只负责读取字节并转交。
  ModSecurity 的响应阶段尚未移植。与 C 实现的差异见 `rust/README.md`。
* 覆盖率只需一条命令：`mise run coverage` 打印单元测试的每模块覆盖率，
  `mise run coverage-e2e` 额外构建插桩 nginx 并跑自研端到端与 `Test::Nginx`
  套件。
* 验证码端点（`waf_captcha api=https://...`）的 SSL 上下文现在随配置释放，
  此前每次配置加载都会泄漏一份。
* `mise run test-valgrind` 在 valgrind 下运行 `Test::Nginx` 模板与自研端到端
  检查；CI 在 stable 分支的静态模块组合上运行它。
* 核心对共享内存的访问统一经过持有 zone 锁的守卫：胶水不再提供"自己加锁"的
  分配入口，操作提前返回（或 panic）也不会把 zone 锁死；顺带修掉三处提前返回
  未解锁的路径。
* 计数表不再退化成整表扫描：一次探测最多走过 64 个槽位，被遗忘或过期的条目会被
  下一个经过它的地址复用，表到达 3/4 占用后淘汰的是本次探测经过的条目。zone
  能记住的地址数与之前一致，但表的共享内存占用从段的 ~9.4% 涨到 ~12.5%，升级后
  的第一次 reload 会重建一次 zone。
* 共享内存 zone 的结构在读取前先校验：核心跟随的每个指针都必须落在段内，表头必须
  描述得下它的槽位；校验失败的目录条目（或目录链）会被丢弃并重建，而不是被当成
  越出段的切片使用。zone 被 bug、崩溃或其它进程写坏时因此可以自愈。
* 核心的内存安全现在由 sanitizer 与 fuzzer 把关：`mise run test-asan` 在
  AddressSanitizer 下跑单测，`mise run test-miri` 在 Miri 下跑共享内存表，
  `mise run fuzz` 用 cargo-fuzz 模糊表状态机，`mise run test-sanitize-nginx`
  用 AddressSanitizer 构建的 nginx 跑端到端检查。CI 四项都会执行。
* 共享内存区的表现在要求“表头 + 其描述的槽位数组”整体位于段内：容量只满足
  整个段的大小、却超出表头之后空间的表（被 bug、崩溃或其它进程写坏的表）此前
  会被当成越出段的切片使用。
* 友好爬虫或验证码服务商解析失败时的 resolver 上下文不再被重复释放：
  `ngx_resolve_name()`/`ngx_resolve_addr()` 报告失败时已经释放了上下文，
  模块不再在该分支上调用 `ngx_resolve_*_done()`。
* 验证码服务商应答的分块（chunked）报文中，如果 chunk 大小的末尾 CRLF 在地址
  空间里放不下，该报文会被拒绝：此前用于计算报文边界的加法会溢出（debug 构建
  在加法处 panic，release 构建在随后的切片处 panic）。
* `$waf_spend` 复制的字节数不再可能超过格式化它的栈缓冲区：`snprintf()`
  返回的是“本该写入”的长度，而拷贝此前把它当成了要从栈缓冲区读取的长度。
* 同一上下文中的 `waf_captcha` 指定多个 `api=https://...` 时，其端点的 SSL
  上下文只保留一条池清理：模块会释放被后续指令替换掉的上下文，并且只注册
  一次清理，配置释放时不再对同一个 `SSL_CTX` 释放两次。
* `waf_captcha` 支持 Cloudflare Turnstile（`prov=Turnstile`）：默认端点使用
  Turnstile 的 siteverify API，判定只要求应答携带 `success`，同时接受原生的
  `cf-turnstile-response` 与兼容模式的 `g-recaptcha-response`，并自带 Turnstile
  验证页（issue #153）。
* `waf_captcha max_fails=N` 现在按配置值生效：C 实现使用 `max(N, 20)` 的下限，
  小于 20 的 N 都会表现为 20；现在允许 N 次失败，第 N+1 次返回 429
  （issue #152）。
* `waf_action modsecurity=FOLLOW` 现在使用配置的 `waf_block_page`，并保留
  ModSecurity 规则给出的状态码；C 实现只返回裸状态码，响应由 nginx 的错误页
  处理（issue #114）。
* 验证码与 under attack 页面的 Cookie 改用 `cookie` crate 解析，因此
  nginx 1.29.6 对 "Cookie" 解析的改动（issue #154）不会影响它们。C 实现使用
  `ngx_http_parse_multi_header_lines()` 查找 Cookie；该函数在 1.29.6 起不再把
  `;` 当分隔符，导致每个访客都被重新挑战。

见 [https://github.com/ADD-SP/ngx_waf-docs/blob/master/docs/zh-cn/changes/overview.md](https://github.com/ADD-SP/ngx_waf-docs/blob/master/docs/zh-cn/changes/overview.md)。
