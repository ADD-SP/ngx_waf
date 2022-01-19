use Test::Nginx::Socket 'no_plan';

run_tests();


__DATA__

=== TEST: Cache

--- main_config
${main_config}

--- config
waf on;
waf_mode FULL;
waf_rule_path ${base_dir}/waf/rules/;
waf_cc_deny off rate=100r/m;
waf_cache on capacity=1;

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