use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

=== TEST: CC wihout CAPTCHA

--- http_config

waf_zone name=ngx_waf_test size=10m;

--- config
waf on;
waf_mode FULL;
waf_rule_path ${base_dir}/waf/rules/;
waf_cc_deny on rate=1r/h zone=ngx_waf_test:test;
waf_cache off capacity=50;

location /t {
    waf_cc_deny off rate=1r/h;
}

--- pipelined_requests eval
[
    "GET /",
    "GET /",
    "GET /",
    "GET /",
    "GET /",
    "GET /t",
    "GET /t",
    "GET /t",
    "GET /t",
    "GET /t"
]

--- error_code eval
[
    200,
    503,
    503,
    503,
    503,
    404,
    404,
    404,
    404,
    404
]


=== TEST: CC with CAPTCHA (1)

--- http_config

waf_zone name=ngx_waf_test size=10m;

--- config
waf on;
waf_mode FULL;
waf_rule_path ${base_dir}/waf/rules/;
waf_cc_deny CAPTCHA rate=1r/h duration=1h zone=ngx_waf_test:test;
waf_cache off capacity=50;
waf_captcha off prov=hCaptcha file=${base_dir}/waf/hCaptcha.html secret=xx;

location /t {
    waf_cc_deny off;
}

--- pipelined_requests eval
[
    "GET /",
    "GET /",
    "GET /",
    "GET /",
    "GET /",
    "POST /captcha\nh-captcha-response=xxxx",
    "POST /captcha\nh-captcha-response=xxxx",
    "GET /t",
    "GET /t"
]

--- error_code eval
[
    200,
    503,
    503,
    503,
    503,
    200,
    200,
    404,
    404
]


=== TEST: CC with CAPTCHA (2)

--- http_config

waf_zone name=ngx_waf_test size=10m;

--- config
waf on;
waf_mode FULL;
waf_rule_path ${base_dir}/waf/rules/;
waf_cc_deny CAPTCHA rate=1r/h duration=1h zone=ngx_waf_test:test;
waf_cache off capacity=50;
waf_captcha off prov=hCaptcha file=${base_dir}/waf/hCaptcha.html secret=xx;

--- pipelined_requests eval
[
    "GET /",
    "GET /",
    "GET /",
    "POST /captcha\nh-captcha-response=xxxx",
    "POST /captcha\nh-captcha-response=xxxx",
    "POST /captcha\nh-captcha-response=xxxx",
    "POST /captcha\nh-captcha-response=xxxx",
    "GET /",
    "GET /"
]

--- response_body_like eval
[
    "work",
    "captcha",
    "captcha",
    "bad",
    "bad",
    "bad",
    "503",
    "503",
    "503"
]

--- error_code eval
[
    200,
    503,
    503,
    200,
    200,
    200,
    503,
    503,
    503
]


=== TEST: CC with CAPTCHA (3)

--- http_config

waf_zone name=ngx_waf_test size=10m;

--- config
waf on;
waf_mode FULL;
waf_rule_path ${base_dir}/waf/rules/;
waf_cc_deny CAPTCHA rate=1r/h duration=1h zone=ngx_waf_test:test;
waf_cache off capacity=50;
waf_captcha off prov=hCaptcha file=${base_dir}/waf/hCaptcha.html secret=xx;

--- pipelined_requests eval
[
    "GET /",
    "GET /",
    "GET /",
    "GET /",
    "GET /",
    "GET /",
    "GET /",
    "GET /",
    "GET /",
    "GET /",
    "GET /",
    "GET /",
    "GET /",
    "GET /",
    "GET /",
    "GET /",
    "GET /",
    "GET /",
    "GET /",
    "GET /",
    "GET /",
    "GET /"
]

--- response_body_like eval
[
    "work",
    "captcha",
    "captcha",
    "captcha",
    "captcha",
    "captcha",
    "captcha",
    "captcha",
    "captcha",
    "captcha",
    "captcha",
    "captcha",
    "captcha",
    "captcha",
    "captcha",
    "captcha",
    "captcha",
    "captcha",
    "captcha",
    "captcha",
    "captcha",
    "503"
]

--- error_code eval
[
    200,
    503,
    503,
    503,
    503,
    503,
    503,
    503,
    503,
    503,
    503,
    503,
    503,
    503,
    503,
    503,
    503,
    503,
    503,
    503,
    503,
    503
]
