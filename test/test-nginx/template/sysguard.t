use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

=== TEST: Sysguard

--- main_config
${main_config}

--- config
waf on;
waf_mode FULL;
waf_rule_path ${base_dir}/waf/rules/;
waf_sysguard on mem=0.01;

--- request
GET /

--- error_code chomp
503