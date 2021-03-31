---
title: FAQ
lang: en
---

# FAQ

## ./configure: error: the ngx_http_waf_module module requires the uthash library.

This module requires the `uthash` library, which you can install via the package manager.

### Ubuntu And Debian

```sh
sudo apt-get update
sudo apt-get install uthash-dev
```

### Centos8

```sh
dnf --enablerepo=PowerTools install uthash-devel
```

### Alpine

```sh
apk update
apk add --upgrade uthash-dev
```

### Other

See [https://pkgs.org/download/uthash-devel](https://pkgs.org/download/uthash-devel) and 
[https://pkgs.org/download/uthash-dev](https://pkgs.org/download/uthash-dev)。

## How does this module perform?

IP inspection and CC defense take constant time, other inspections take `O(nm)`, where `n` is the number of relevant rules and `m` is the time complexity to perform regular matching, but the results of this inspection are automatically cached after each inspection, so that the next time the same target is inspected, the cache can be used instead of checking all the rules. The result of the POST request body check is not cached.

## Cache Policy

LRU

## Post Inspection Failure

For performance reasons, this module will inspect whether it is in the memory before inspecting the request body. If it is, it will inspect normally, otherwise skip the inspection. You can try to edit nginx.conf.

```nginx
http {
    ...
    client_body_buffer_size: 10M;
    client_body_in_file_only: off;
    ...
}
```
[client_body_buffer_size](https://nginx.org/en/docs/http/ngx_http_core_module.html#client_body_buffer_size) 
and [client_body_in_file_only](https://nginx.org/en/docs/http/ngx_http_core_module.html#client_body_in_file_only).

## fork() failed while spawning "worker process" (12: Cannot allocate memory)

It may be caused by excessive use of `nginx -s reload`. The module requests some memory when reading the configuration, but somehow the memory is not released immediately after `nginx -s reload`, so frequent `nginx -s reload` in a short period of time will most likely cause this error.

## Can I change the rules at runtime?

No, this module only reads the rules when nginx starts and not afterwards.
