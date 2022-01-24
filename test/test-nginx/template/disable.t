use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

=== TEST: General

--- main_config
${main_config}

--- config
waf off;
waf_mode FULL;
waf_rule_path ${base_dir}/waf/rules/;
waf_cc_deny on rate=100r/m;
waf_cache on capacity=50m;

--- request
GET /www.bak

--- error_code chomp
404