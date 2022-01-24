use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

=== TEST: General

--- main_config
${main_config}

--- config
waf on;
waf_mode GET UA;
waf_rule_path ${base_dir}/waf/rules/;
waf_cc_deny off rate=100r/m;
waf_verify_bot strict;

--- request
GET /

--- more_headers

--- error_code chomp
200

=== TEST: Fake Googlebot

--- main_config
${main_config}

--- config
waf on;
waf_mode GET UA;
waf_rule_path ${base_dir}/waf/rules/;
waf_cc_deny off rate=100r/m;
waf_verify_bot strict;

--- request
GET /

--- more_headers
User-Agent: Googlebot

--- error_code chomp
403

=== TEST: Fake bingbot

--- main_config
${main_config}

--- config
waf on;
waf_mode GET UA;
waf_rule_path ${base_dir}/waf/rules/;
waf_cc_deny off rate=100r/m;
waf_verify_bot strict;

--- request
GET /

--- more_headers
User-Agent: bingbot

--- error_code chomp
403

=== TEST: Fake Baiduspider

--- main_config
${main_config}

--- config
waf on;
waf_mode GET UA;
waf_rule_path ${base_dir}/waf/rules/;
waf_cc_deny off rate=100r/m;
waf_verify_bot strict;

--- request
GET /

--- more_headers
User-Agent: Baiduspider

--- error_code chomp
403

=== TEST: Fake YandexBot

--- main_config
${main_config}

--- config
waf on;
waf_mode GET UA;
waf_rule_path ${base_dir}/waf/rules/;
waf_cc_deny off rate=100r/m;
waf_verify_bot strict;

--- request
GET /

--- more_headers
User-Agent: YandexBot

--- error_code chomp
403

=== TEST: Fake SogouSpider

--- main_config
${main_config}

--- config
waf on;
waf_mode GET UA;
waf_rule_path ${base_dir}/waf/rules/;
waf_cc_deny off rate=100r/m;
waf_verify_bot strict;

--- request
GET /

--- more_headers
User-Agent: Sogou web spider

--- error_code chomp
403