use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

=== TEST: CC

--- config
waf on;
waf_mode FULL;
waf_rule_path /usr/local/nginx/conf/waf/rules/;
waf_cc_deny on rate=1r/h;
waf_cache off capacity=50;

location /t {
    waf_cc_deny off rate=1r/h;
}

--- pipelined_requests eval
[
    "GET /",
    "GET /",
    "GET /t",
    "GET /t"
]

--- error_code eval
[
    200,
    503,
    404,
    404
]

=== TEST: CC with CAPTCHA

--- config
waf on;
waf_mode FULL;
waf_rule_path /usr/local/nginx/conf/waf/rules/;
waf_cc_deny CAPTCHA rate=1r/h duration=1h;
waf_cache off capacity=50;
waf_captcha off prov=hCaptcha file=/usr/local/nginx/conf/waf/hCaptcha.html secret=xx;

location /t {
    waf_cc_deny off;
}

--- pipelined_requests eval
[
    "GET /",
    "GET /",
    "GET /",
    "POST /captcha\nh-captcha-response=xxxx",
    "GET /t",
    "GET /t"
]

--- error_code eval
[
    200,
    503,
    503,
    200,
    404,
    404
]

--- ONLY
