use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

=== TEST: General

--- config
waf on;
waf_mode GET UA;
waf_rule_path ${base_dir}/waf/rules/;
waf_cc_deny off rate=100r/m;
waf_cache off capacity=50;
waf_verify_bot strict;

--- request
GET /

--- more_headers

--- error_code chomp
200

=== TEST: Fake Googlebot

--- config
waf on;
waf_mode GET UA;
waf_rule_path ${base_dir}/waf/rules/;
waf_cc_deny off rate=100r/m;
waf_cache off capacity=50;
waf_verify_bot strict;

--- request
GET /

--- more_headers
User-Agent: Googlebot

--- error_code chomp
403

=== TEST: Fake bingbot

--- config
waf on;
waf_mode GET UA;
waf_rule_path ${base_dir}/waf/rules/;
waf_cc_deny off rate=100r/m;
waf_cache off capacity=50;
waf_verify_bot strict;

--- request
GET /

--- more_headers
User-Agent: bingbot

--- error_code chomp
403

=== TEST: Fake Baiduspider

--- config
waf on;
waf_mode GET UA;
waf_rule_path ${base_dir}/waf/rules/;
waf_cc_deny off rate=100r/m;
waf_cache off capacity=50;
waf_verify_bot strict;

--- request
GET /

--- more_headers
User-Agent: Baiduspider

--- error_code chomp
403

=== TEST: Fake YandexBot

--- config
waf on;
waf_mode GET UA;
waf_rule_path ${base_dir}/waf/rules/;
waf_cc_deny off rate=100r/m;
waf_cache off capacity=50;
waf_verify_bot strict;

--- request
GET /

--- more_headers
User-Agent: YandexBot

--- error_code chomp
403