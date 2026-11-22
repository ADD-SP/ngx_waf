use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

=== TEST: General

--- config
waf off;
waf_cc_deny on rate=100r/m;

--- request
GET /www.bak

--- error_code chomp
404