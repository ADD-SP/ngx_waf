use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

=== TEST: General

--- config
waf off;
waf_mode FULL;
waf_rule_path ${base_dir}/waf/rules/;
waf_cc_deny rate=100r/m;
waf_cache capacity=50;

--- request
GET /www.bak

--- error_code chomp
404