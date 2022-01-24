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

--- request
GET /

--- more_headers
User-Agent: test-user-agent

--- error_code chomp
200


=== TEST: White user-agent

--- main_config
${main_config}

--- config
waf on;
waf_mode FULL;
waf_rule_path ${base_dir}/waf/rules/;
waf_cc_deny off rate=100r/m;

--- request
GET /www.bak

--- more_headers
User-Agent: TEST_WHITE_USER_AGENT

--- error_code chomp
404


=== TEST: Black user-agent

--- main_config
${main_config}

--- config
waf on;
waf_mode FULL;
waf_rule_path ${base_dir}/waf/rules/;
waf_cc_deny off rate=100r/m;

--- request
GET /

--- more_headers
User-Agent: / SF/

--- error_code chomp
403