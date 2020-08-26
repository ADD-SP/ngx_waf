# 更新日志

## [未发布]

### 新增

### 改动

### 修复

## [1.0.1] - 2020-08-22

### 新增

+ 增加了新的配置项（[3214fc8](https://github.com/ADD-SP/ngx_waf/commit/3214fc88d565ed47daa4bdac4f0edb7d1785ed75)）
    + waf_check_ipv4:
        + 配置语法: `waf_check_ipv4 [ on | off ];`
        + 默认值：`on`
        + 配置段: server
        + 作用：是否启用 IPV4 检查。
    + waf_check_url:
        + 配置语法: `waf_check_url [ on | off ];`
        + 默认值：`on`
        + 配置段: server
        + 作用：是否启用 URL 检查。
    + waf_check_args:
        + 配置语法: `waf_check_args [ on | off ];`
        + 默认值：`on`
        + 配置段: server
        + 作用：是否启用 Args 检查。
    + waf_check_ua:
        + 配置语法: `waf_check_ua [ on | off ];`
        + 默认值：`on`
        + 配置段: server
        + 作用：是否启用 User-Agent 检查。
    + waf_check_referer:
        + 配置语法: `waf_check_referer [ on | off ];`
        + 默认值：`on`
        + 配置段: server
        + 作用：是否启用 Referer 检查。
    + waf_check_cookie:
        + 配置语法: `waf_check_cookie [ on | off ];`
        + 默认值：`on`
        + 配置段: server
        + 作用：是否启用 Cookie 检查。
    + waf_check_post:
        + 配置语法: `waf_check_post [ on | off ];`
        + 默认值：`off`
        + 配置段: server
        + 作用：是否启用 POST 检查。
    + waf_cc_deny:
        + 配置语法: `waf_cc_deny [ on | off ];`
        + 默认值：`off`
        + 配置段: server
        + 作用：是否启用 CC 防御。


### 改动

+ `waf_mult_mount`现在只允许写在`server`段中（[3214fc8](https://github.com/ADD-SP/ngx_waf/commit/3214fc88d565ed47daa4bdac4f0edb7d1785ed75)）。
    + waf_mult_mount:
        + 配置语法: `waf_mult_mount [ on | off ];`
        + 默认值：`off`
        + 配置段: server
        + 作用：进行多阶段检查，当`nginx.conf`存在地址重写的情况下（如`rewrite`配置）建议启用，反之建议关闭。
+ 更改现有的配置项关键字，删除了`ngx_`前缀（[8b3e416](https://github.com/ADD-SP/ngx_waf/commit/8b3e416cdfdc7e073a3392fc9ec027a4138af453)）。
    + waf:
        + 配置语法: `waf [ on | off ];`
        + 默认值：`off`
        + 配置段: server
        + 作用：是否启用本模块。
    + waf_rule_path:
        + 配置语法: `waf_rule_path dir;`
        + 默认值：无
        + 配置段: server
        + 作用：规则文件所在目录，且必须以`/`结尾。
    + waf_mult_mount:
        + 配置语法: `waf_mult_mount [ on | off ];`
        + 默认值：`off`
        + 配置段: http
        + 作用：进行多阶段检查，当`nginx.conf`存在地址重写的情况下（如`rewrite`配置）建议启用，反之建议关闭。
+ 更新 referer 的默认规则，具体一点就是拷贝`rules/url`的内容到`rules/referer`中（[55f5e26](https://github.com/ADD-SP/ngx_waf/commit/55f5e26b6135af382b1db88057f5143631848ae7)）。

### 修复

+ 修复 CC 防御功能检测逻辑的错误，该错误会导致实际的频率限制要远小于用户指定的限制，容易将正常访问识别为 CC 攻击（[9cb51bb](https://github.com/ADD-SP/ngx_waf/commit/9cb51bba0cdf10c2fd1ac0a482d7435dcfdee93d)）（[171721c](https://github.com/ADD-SP/ngx_waf/commit/171721cee861022e9f3db5fceeb16051b90a5e54)）。
+ 现在会检查 rules/ipv4 和 rules/white-ipv4 这两个文件中的 IPV4 地址或地址块是否合法（[fc09f04](https://github.com/ADD-SP/ngx_waf/commit/fc09f045d1e9ac774a919181a15c20a6c777a276)）（[2e7f624](https://github.com/ADD-SP/ngx_waf/commit/2e7f624581d8d85a23d6470acced9acc3e2840b2)）。

## [1.0.0] - 2020-08-18

### 新增

+ 改进日志格式（[bd112ec](https://github.com/ADD-SP/ngx_waf/commit/bd112ecacd9356ee1e0731634cfc197034d25c88)）。基本格式为`xxxxx, ngx_waf: [拦截类型][对应规则], xxxxx`，具体可看下面的例子。
    ```text
    2020/01/20 22:56:30 [alert] 24289#0: *30 ngx_waf: [BLACK-URL][(?i)(?:/\.env$)], client: 192.168.1.1, server: example.com, request: "GET /v1/.env HTTP/1.1", host: "example.com", referrer: "http:/example.com/v1/.env"

    2020/01/20 22:58:40 [alert] 24678#0: *11 ngx_waf: [BLACK-POST][(?i)(?:select.+(?:from|limit))], client: 192.168.1.1, server: example.com, request: "POST /xmlrpc.php HTTP/1.1", host: "example.com", referrer: "https://example.com/"
    ```
+ 新增三个内置变量（[92d6d84](https://github.com/ADD-SP/ngx_waf/commit/92d6d847840ada57bbc54ffe2c0980b118a37a30)）
    + `$waf_blocked`: 本次请求是否被本模块拦截，如果拦截了则其的值为`'true'`,反之则为`'false'`。
    + `$waf_rule_type`：如果本次请求被本模块拦截，则其值为触发的规则类型。下面是可能的取值。若没有生效则其值为`'null'`。
        + `'BLACK-IPV4'`
        + `'BLACK-URL'`
        + `'BLACK-ARGS'`
        + `'BLACK-USER-AGENT'`
        + `'BLACK-REFERER'`
        + `'BLACK-COOKIE'`
        + `'BLACK-POST'`
    + `'$waf_rule_details'`：如果本次请求被本模块拦截，则其值为触发的具体的规则的内容。若没有生效则其值为`'null'`。
+ 支持过滤 POST 请求（[b46641e](https://github.com/ADD-SP/ngx_waf/commit/b46641eb8473c6dcb6afe9ed73f94712300d176f)）。
+ 新配置项`ngx_waf_mult_mount`用于增加拦截面（[e1b500d](https://github.com/ADD-SP/ngx_waf/commit/e1b500de349e017b67f334878342bdd6a34d22b8)），典型的应用场景是存在`rewrite`的情况下重写前后均会对 URL 进行一次检测。
+ 支持 CC 防御功能（[3a93e19](https://github.com/ADD-SP/ngx_waf/commit/3a93e190b8cb78fcd7a0197f76298c010169d113)）。

### 改动

+ 增加默认的 POST 过滤规则（[68dd102](https://github.com/ADD-SP/ngx_waf/commit/68dd102e011acfd819669d60a35d315365d26a16)）
+ 更新默认规则（[55f0a48](https://github.com/ADD-SP/ngx_waf/commit/55f0a4824bafb67f562909bdb58292cfce1059ae)）。
+ 修改规则优先级（[3c388c8](https://github.com/ADD-SP/ngx_waf/commit/3c388c85e30528b66306ca780524c7d663277f07)）（[248958d](https://github.com/ADD-SP/ngx_waf/commit/248958d3a0ef27dd14acc63a503e97931841f18a)）（[b46641e](https://github.com/ADD-SP/ngx_waf/commit/b46641eb8473c6dcb6afe9ed73f94712300d176f)）（(92447a3)[https://github.com/ADD-SP/ngx_waf/commit/92447a39d6a36ab027b0ead0daa0fe2b3b74ff29]），现在的优先级为（靠上的优先生效）：
    1. IP 白名单
    2. IP 黑名单
    3. CC 防御
    4. URL 白名单
    5. URL 黑名单
    6. Args 黑名单
    7. UserAgent 黑名单
    8. Referer 白名单
    9. Referer 黑名单
    10. Cookie 黑名单
    11. POST 黑名单

### 修复

+ IPV4 黑白名单功能失效（[231f94a](https://github.com/ADD-SP/ngx_waf/commit/231f94aa5383fe8f6cdc0fbc3cd2dcadb7606881)）。
+ 当 User-agent 为空时会触发 segmentation fault（[bf33b36](https://github.com/ADD-SP/ngx_waf/commit/bf33b366232b7f5e05379d5e10ab006696189ea6)）。
+ 启用 CC 防御后会有内存泄漏（[be58d18](https://github.com/ADD-SP/ngx_waf/commit/be58d189b4c95be066623604124b02a9bf174e7f)）。

