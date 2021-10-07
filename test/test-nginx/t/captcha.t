use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

=== TEST: hCaptcha

--- config
waf on;
waf_mode FULL;
waf_rule_path /usr/local/nginx/conf/waf/rules/;
waf_cc_deny off rate=100r/m;
waf_cache off capacity=50;
waf_captcha on prov=hCaptcha file=/usr/local/nginx/conf/waf/hCaptcha.html secret=xx;

--- request
GET /

--- response_body_like chomp
captcha

--- error_code chomp
503

=== TEST: reCAPTCHAv2 checkbox

--- config
waf on;
waf_mode FULL;
waf_rule_path /usr/local/nginx/conf/waf/rules/;
waf_cc_deny off rate=100r/m;
waf_cache off capacity=50;
waf_captcha on prov=reCAPTCHAv2 file=/usr/local/nginx/conf/waf/reCAPTCHAv2_Checkbox.html secret=xx;

--- request
GET /

--- response_body_like chomp
captcha

--- error_code chomp
503

=== TEST: reCAPTCHAv2 invisible

--- config
waf on;
waf_mode FULL;
waf_rule_path /usr/local/nginx/conf/waf/rules/;
waf_cc_deny off rate=100r/m;
waf_cache off capacity=50;
waf_captcha on prov=reCAPTCHAv2 file=/usr/local/nginx/conf/waf/reCAPTCHAv2_Invisible.html secret=xx;

--- request
GET /

--- response_body_like chomp
captcha

--- error_code chomp
503

=== TEST: reCAPTCHAv3

--- config
waf on;
waf_mode FULL;
waf_rule_path /usr/local/nginx/conf/waf/rules/;
waf_cc_deny off rate=100r/m;
waf_cache off capacity=50;
waf_captcha on prov=reCAPTCHAv3 file=/usr/local/nginx/conf/waf/reCAPTCHAv3.html secret=xx score=0.5;

--- request
GET /

--- response_body_like chomp
captcha

--- error_code chomp
503