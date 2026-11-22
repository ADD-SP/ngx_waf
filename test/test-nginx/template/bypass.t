use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

=== TEST: General

--- config
waf bypass;

--- request
GET /www.bak

--- error_code chomp
404