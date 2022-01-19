use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

=== TEST: No method GET

--- main_config
${main_config}

--- config
waf on;
waf_mode FULL !GET;
waf_rule_path ${base_dir}/waf/rules/;waf_cc_deny off rate=100r/m;
waf_cc_deny off rate=100r/m;
waf_cache off capacity=50;

--- request
GET /www.bak


--- error_code chomp
404

=== TEST: No method POST

--- main_config
${main_config}

--- config
waf on;
waf_mode FULL !POST;
waf_rule_path ${base_dir}/waf/rules/;waf_cc_deny off rate=100r/m;
waf_cc_deny off rate=100r/m;
waf_cache off capacity=50;

--- request
POST /www.bak


--- error_code chomp
404

=== TEST: No method HEAD

--- main_config
${main_config}

--- config
waf on;
waf_mode FULL !HEAD;
waf_rule_path ${base_dir}/waf/rules/;
waf_cc_deny off rate=100r/m;
waf_cache off capacity=50;

--- request
HEAD /www.bak


--- error_code chomp
404
