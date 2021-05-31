---
title: Test
lang: en
---

# Test

## Quick Test

Visit `/www.bak` and if a 403 status code is returned, the module is successfully started.

## Performance Test

### Example Test

#### Test Description

* ngx_waf v5.1.1.
* Approximately 210,000 IPV4 whitelist rules were used.
* About 210,000 IPV4 blacklist rules were used.
* Approximately 48,000 IPV6 whitelist rules were used.
* Approximately 48,000 IPV6 blacklist rules were used.
* 100,000 URL blacklist rules used, obtained by random string generator.
* 100,000 URL whitelist rules were used, obtained by a random string generator.
* Uses 5000 random strings, obtained by a random string generator. One of them is randomly selected as the URI for each request to send a GET request.
* The test lasts 30 minutes.
* Tested twice, once with the firewall on and once with the firewall off.

::: tip NOTE

The IP for testing is obtained from [IPdney](https://www.ipdeny.com/ipblocks/).

:::

Configuration used for testing.

```nginx
master_process on;
worker_processes  1;

http {
    server {
        listen 80;
        server_name  localhost;

        access_log off;
        
        waf on;
        waf_mode DYNAMIC !CC !POST;
        waf_rule_path /usr/local/src/ngx_waf/rules/;
        waf_cache capacity=6000 interval=1h percent=50;

        location / {
            default_type text/html;
            return 200 'hello';
        }
    }
}
```

#### Test Command

```sh
wrk -c 100 -d 30m -t 1 -s test/wrk/rand.lua --latency http://localhost/ -- /path/to/rand-str.txt
```

#### Test Results

With the firewall on, QPS(Queries Per Second) is reduced by about 4%.

```sh
# waf on;
wrk -c 100 -d 30m -t 1 -s ngx_waf/test/wrk/rand.lua --timeout 1m --latency http://localhost/ -- /usr/local/src/ngx_waf/txt.txt

Running 30m test @ http://localhost/
  1 threads and 100 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    78.56ms  340.74ms   3.97s    94.52%
    Req/Sec    67.33k    25.42k   95.38k    86.58%
  Latency Distribution
     50%    1.14ms
     75%    1.48ms
     90%    4.84ms
     99%    1.97s
  120532104 requests in 30.00m, 17.06GB read
Requests/sec:  66959.26
Transfer/sec:      9.71MB


# waf off;
wrk -c 100 -d 30m -t 1 -s ngx_waf/test/wrk/rand.lua --timeout 1m --latency http://localhost/ -- /usr/local/src/ngx_waf/txt.txt

Running 30m test @ http://localhost/
  1 threads and 100 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   803.44us    0.87ms  40.32ms   95.23%
    Req/Sec    70.69k    10.46k  105.82k    81.15%
  Latency Distribution
     50%  590.00us
     75%  760.00us
     90%    1.25ms
     99%    4.25ms
  126562158 requests in 30.00m, 17.92GB read
Requests/sec:  70310.93
Transfer/sec:     10.19MB
```

### Test By Yourself

You can use [wrk](https://github.com/wg/wrk) to perform performance tests on this module.

This project provides wrk's lua script for testing. The path of the script is `test/wrk/rand.lua` and its function is to send GET requests using a random URI. You need to provide it with a text file containing a certain number of random strings, one random string per line. Then test it with the following command.

```sh
wrk -c 100 -d 1m -t 1 -s test/wrk/rand.lua --latency http://localhost/ -- /path/to/rand-str.txt
```