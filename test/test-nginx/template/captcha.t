use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

=== TEST: hCaptcha

--- config
waf on;
waf_mode FULL;
waf_rule_path ${base_dir}/waf/rules/;
waf_cc_deny off rate=100r/m;
waf_cache off capacity=50;
waf_captcha on prov=hCaptcha file=${base_dir}/waf/hCaptcha.html secret=xx;

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



=== TEST: reCAPTCHAv2 checkbox

--- config
waf on;
waf_mode FULL;
waf_rule_path ${base_dir}/waf/rules/;
waf_cc_deny off rate=100r/m;
waf_cache off capacity=50;
waf_captcha on prov=reCAPTCHAv2 file=${base_dir}/waf/reCAPTCHAv2_Checkbox.html secret=xx;

--- pipelined_requests eval
[
    "GET /",
    "GET /",
    "POST /captcha\ng-recaptcha-response=xxxx"
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

=== TEST: reCAPTCHAv2 invisible

--- config
waf on;
waf_mode FULL;
waf_rule_path ${base_dir}/waf/rules/;
waf_cc_deny off rate=100r/m;
waf_cache off capacity=50;
waf_captcha on prov=reCAPTCHAv2 file=${base_dir}/waf/reCAPTCHAv2_Invisible.html secret=xx;

--- pipelined_requests eval
[
    "GET /",
    "GET /",
    "POST /captcha\ng-recaptcha-response=xxxx"
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

=== TEST: reCAPTCHAv3

--- config
waf on;
waf_mode FULL;
waf_rule_path ${base_dir}/waf/rules/;
waf_cc_deny off rate=100r/m;
waf_cache off capacity=50;
waf_captcha on prov=reCAPTCHAv3 file=${base_dir}/waf/reCAPTCHAv3.html secret=xx score=0.5;

--- pipelined_requests eval
[
    "GET /",
    "GET /",
    "POST /captcha\ng-recaptcha-response=xxxx"
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
