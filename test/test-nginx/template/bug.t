use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

=== TEST: CAPTCHA failed

当在 precontent 阶段出现内部重定向时，模块已经挂载的内容处理函数会被摘掉。

此问题最早发现于 v9.0.5，已经于 v9.0.6 修复。

--- config
waf on;
waf_mode FULL;
waf_rule_path ${base_dir}/waf/rules/;
waf_cc_deny off rate=100r/m;
waf_cache off capacity=50;
waf_captcha on prov=hCaptcha file=${base_dir}/waf/hCaptcha.html secret=xx;

location /captcha {
    try_files \$uri \$uri/ /t;
}

--- pipelined_requests eval
[
    "GET /",
    "GET /",
    "POST /captcha\nh-captcha-response=xxxx"
]


--- more_headers eval
[
    "",
    "Cookie: __waf_captcha_time=123456; __waf_captcha_uid=123456; __waf_captcha_hmac=123456",
    ""
]

--- error_code eval
[
    503,
    503,
    200
]
