use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

=== TEST: hCaptcha

--- main_config
${main_config}

--- config
waf on;
waf_mode FULL;
waf_rule_path ${base_dir}/waf/rules/;
waf_cc_deny off rate=100r/m;
waf_captcha on prov=hCaptcha secret=xx sitekey=xx;

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

--- main_config
${main_config}

--- config
waf on;
waf_mode FULL;
waf_rule_path ${base_dir}/waf/rules/;
waf_cc_deny off rate=100r/m;
waf_captcha on prov=reCAPTCHAv2:checkbox secret=xx sitekey=xx;

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

--- main_config
${main_config}

--- config
waf on;
waf_mode FULL;
waf_rule_path ${base_dir}/waf/rules/;
waf_cc_deny off rate=100r/m;
waf_captcha on prov=reCAPTCHAv2:invisible secret=xx sitekey=xx;

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

--- main_config
${main_config}

--- config
waf on;
waf_mode FULL;
waf_rule_path ${base_dir}/waf/rules/;
waf_cc_deny off rate=100r/m;
waf_captcha on prov=reCAPTCHAv3 secret=xx score=0.5 sitekey=xx;

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
