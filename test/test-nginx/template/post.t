use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

=== TEST: General

--- main_config
${main_config}

--- config
waf on;
waf_mode GET RBODY;
waf_rule_path ${base_dir}/waf/rules/;
waf_cc_deny off rate=100r/m;
waf_cache off capacity=50;

location /t {
}

--- request
POST /
s=test

--- error_code chomp
405


=== TEST: White POST

--- main_config
${main_config}

--- config
waf on;
waf_mode FULL;
waf_rule_path ${base_dir}/waf/rules/;
waf_cc_deny off rate=100r/m;
waf_cache on capacity=50;

--- request
POST /www.bak
TEST_WHITE_POST

--- error_code chomp
404


=== TEST: Black POST

--- main_config
${main_config}

--- config
waf on;
waf_mode FULL;
waf_rule_path ${base_dir}/waf/rules/;
waf_cc_deny off rate=100r/m;
waf_cache on capacity=50;

location /t {
}

--- request
POST /
onload=

--- error_code chomp
403