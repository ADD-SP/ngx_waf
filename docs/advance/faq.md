---
title: FAQ
lang: en
---

# FAQ

## How does this module perform?

The time complexity of IP inspecting and Anti Challenge Collapsar is O(1), and the other inspecting are O(nm), where n is the number of relevant rules and m is the time complexity of performing regular expression matching.

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
