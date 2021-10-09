use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

=== TEST: Cache

--- config
waf on;
waf_mode FULL !CC;
waf_rule_path ${base_dir}/waf/rules/;
waf_cache capacity=1;

--- pipelined_requests eval
[
    "GET /test0",
    "GET /test0",
    "GET /test1",
    "GET /test1",
    "GET /test2",
    "GET /test2",
    "GET /test3",
    "GET /test3",
    "GET /test4",
    "GET /test4",
]

--- error_code eval
[
    404,
    404,
    404,
    404,
    404,
    404,
    404,
    404,
    404,
    404
]