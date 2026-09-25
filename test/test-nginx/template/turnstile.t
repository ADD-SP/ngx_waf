use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

# The official Turnstile test keys, see
# https://developers.cloudflare.com/turnstile/troubleshooting/testing/.
# The always-pass secret accepts any response token, so the case reaches the
# real siteverify endpoint of Cloudflare without a browser widget.

=== TEST: Turnstile test key passes

--- config
waf on;
waf_mode FULL;
waf_rule_path ${base_dir}/waf/rules/;
waf_cc_deny off rate=100r/m;
waf_cache off capacity=50;
waf_captcha on prov=Turnstile secret=1x0000000000000000000000000000000AA sitekey=1x00000000000000000000AA;

--- request
POST /captcha
cf-turnstile-response=dummy

--- error_code: 200
--- response_body_like: ^good$


=== TEST: Turnstile test key accepts the reCAPTCHA compatible field

--- config
waf on;
waf_mode FULL;
waf_rule_path ${base_dir}/waf/rules/;
waf_cc_deny off rate=100r/m;
waf_cache off capacity=50;
waf_captcha on prov=Turnstile secret=1x0000000000000000000000000000000AA sitekey=1x00000000000000000000AA;

--- request
POST /captcha
g-recaptcha-response=dummy

--- error_code: 200
--- response_body_like: ^good$


=== TEST: Turnstile failure test key is refused

--- config
waf on;
waf_mode FULL;
waf_rule_path ${base_dir}/waf/rules/;
waf_cc_deny off rate=100r/m;
waf_cache off capacity=50;
waf_captcha on prov=Turnstile secret=2x0000000000000000000000000000000AA sitekey=1x00000000000000000000AA;

--- request
POST /captcha
cf-turnstile-response=dummy

--- error_code: 200
--- response_body_like: ^bad$
