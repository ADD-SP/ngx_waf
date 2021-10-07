use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

=== TEST: cc

--- config
waf on;
waf_mode FULL;
waf_rule_path /usr/local/nginx/conf/waf/rules/;
waf_cc_deny on rate=1r/m;
waf_cache off capacity=50;

--- pipelined_requests eval
[
    "GET /",
    "GET /"
]

--- error_code eval
[
    200,
    503
]

=== TEST: cc with CAPTCHA

--- config
waf on;
waf_mode FULL;
waf_rule_path /usr/local/nginx/conf/waf/rules/;
waf_cc_deny CAPTCHA rate=1r/m;
waf_cache off capacity=50;
waf_http_status cc_deny=444;
waf_captcha off prov=hCaptcha file=/usr/local/nginx/conf/waf/hCaptcha.html secret=xx;

--- pipelined_requests eval
[
    "GET /",
    "GET /"
]

--- error_code eval
[
    200,
    503
]