use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

=== TEST: General

--- config
waf on;
waf_mode GET POST RBODY;
waf_rule_path ${base_dir}/waf/rules/;

location /t {
}

--- request
POST /t
s=test

--- error_code chomp
404

=== TEST: Black POST

--- config
waf on;
waf_mode GET POST RBODY;
waf_rule_path ${base_dir}/waf/rules/;

location /t {
}

--- request
POST /t
onload=

--- error_code chomp
403

