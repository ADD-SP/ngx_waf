#include <ngx_http_waf_module_verify_bot.h>

static ngx_int_t _verify_google_bot(ngx_http_request_t* r);

static ngx_int_t _verify_bing_bot(ngx_http_request_t* r);

static ngx_int_t _verify_baidu_spider(ngx_http_request_t* r);

static ngx_int_t _verify_yandex_bot(ngx_http_request_t* r);

static ngx_int_t _gen_ctx(ngx_http_request_t* r, const char* detail);

ngx_int_t ngx_http_waf_handler_verify_bot(ngx_http_request_t* r, ngx_int_t* out_http_status) {
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, NULL);

    if (loc_conf->waf_verify_bot == 0 || loc_conf->waf_verify_bot == NGX_CONF_UNSET) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Because this Inspection is disabled in the configuration, no Inspection is performed.");
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Processing is complete.");
        return NGX_HTTP_WAF_NOT_MATCHED;
    }

    #define ngx_http_waf_func(handler, bot) {                                   \
        ngx_int_t rc = (handler)(r);                                            \
        if (rc == NGX_HTTP_WAF_FAKE_BOT && loc_conf->waf_verify_bot == 2) {     \
            *out_http_status = loc_conf->waf_http_status;                       \
            if (_gen_ctx(r, (bot)) != NGX_HTTP_WAF_SUCCESS) {                   \
                *out_http_status = NGX_HTTP_INTERNAL_SERVER_ERROR;              \
            }                                                                   \
            return NGX_HTTP_WAF_MATCHED;                                        \
        } else if (rc == NGX_HTTP_WAF_SUCCESS) {                                \
            *out_http_status = NGX_DECLINED;                                    \
            return NGX_HTTP_WAF_MATCHED;                                        \
        }                                                                       \
    }

    ngx_http_waf_func(_verify_google_bot, "GoogleBot");
    ngx_http_waf_func(_verify_bing_bot, "BingBot");
    ngx_http_waf_func(_verify_baidu_spider, "BaiduSpider");
    ngx_http_waf_func(_verify_yandex_bot, "YandexBot");


    #undef ngx_http_waf_func

    return NGX_HTTP_WAF_NOT_MATCHED;
}


static ngx_int_t _verify_google_bot(ngx_http_request_t* r) {
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, NULL);

    if (ngx_http_waf_check_flag(loc_conf->waf_verify_bot_type, NGX_HTTP_WAF_GOOGLE_BOT) != NGX_HTTP_WAF_TRUE) {
        return NGX_HTTP_WAF_FAIL;
    }

    if (r->headers_in.user_agent->value.data == NULL || r->headers_in.user_agent->value.len == 0) {
        return NGX_HTTP_WAF_FAIL;
    }

    if (ngx_regex_exec_array(loc_conf->waf_verify_bot_google_ua_regexp,
                             &r->headers_in.user_agent->value,
                             r->connection->log) != NGX_OK) {
        return NGX_HTTP_WAF_FAIL;
    }

    struct hostent* h = NULL;
    if (r->connection->sockaddr->sa_family == AF_INET) {
        struct sockaddr_in* sin = (struct sockaddr_in*)r->connection->sockaddr;
        h = gethostbyaddr(&sin->sin_addr, sizeof(sin->sin_addr), AF_INET);
    }
#if (NGX_HAVE_INET6)
    else if (r->connection->sockaddr->sa_family == AF_INET6) {
        struct sockaddr_in6* sin6 = (struct sockaddr_in6*)r->connection->sockaddr;
        h = gethostbyaddr(&sin6->sin6_addr, sizeof(sin6->sin6_addr), AF_INET6);
    }
#endif

    if (h == NULL) {
        if (h_errno == HOST_NOT_FOUND) {
            return NGX_HTTP_WAF_FAKE_BOT;
        } else {
            return NGX_HTTP_WAF_FAIL;
        }
    }

    ngx_str_t host;
    host.data = (u_char*)h->h_name;
    host.len = strlen(h->h_name);
    if (ngx_regex_exec_array(loc_conf->waf_verify_bot_google_domain_regexp, &host, r->connection->log) == NGX_OK) {
        return NGX_HTTP_WAF_SUCCESS;
    }

    for (int i = 0; h->h_aliases[i] != NULL; i++) {
        host.data = (u_char*)h->h_aliases[i];
        host.len = strlen(h->h_aliases[i]);
        if (ngx_regex_exec_array(loc_conf->waf_verify_bot_google_domain_regexp, &host, r->connection->log) == NGX_OK) {
            return NGX_HTTP_WAF_SUCCESS;
        }
    }

    return NGX_HTTP_WAF_FAKE_BOT;
}

static ngx_int_t _verify_bing_bot(ngx_http_request_t* r) {
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, NULL);

    if (ngx_http_waf_check_flag(loc_conf->waf_verify_bot_type, NGX_HTTP_WAF_BING_BOT) != NGX_HTTP_WAF_TRUE) {
        return NGX_HTTP_WAF_FAIL;
    }

    if (r->headers_in.user_agent->value.data == NULL || r->headers_in.user_agent->value.len == 0) {
        return NGX_HTTP_WAF_FAIL;
    }

    if (ngx_regex_exec_array(loc_conf->waf_verify_bot_bing_ua_regexp,
                             &r->headers_in.user_agent->value,
                             r->connection->log) != NGX_OK) {
        return NGX_HTTP_WAF_FAIL;
    }

    struct hostent* h = NULL;
    if (r->connection->sockaddr->sa_family == AF_INET) {
        struct sockaddr_in* sin = (struct sockaddr_in*)r->connection->sockaddr;
        h = gethostbyaddr(&sin->sin_addr, sizeof(sin->sin_addr), AF_INET);
    }
#if (NGX_HAVE_INET6)
    else if (r->connection->sockaddr->sa_family == AF_INET6) {
        struct sockaddr_in6* sin6 = (struct sockaddr_in6*)r->connection->sockaddr;
        h = gethostbyaddr(&sin6->sin6_addr, sizeof(sin6->sin6_addr), AF_INET6);
    }
#endif

    if (h == NULL) {
        if (h_errno == HOST_NOT_FOUND) {
            return NGX_HTTP_WAF_FAKE_BOT;
        } else {
            return NGX_HTTP_WAF_FAIL;
        }
    }

    ngx_str_t host;
    host.data = (u_char*)h->h_name;
    host.len = strlen(h->h_name);
    if (ngx_regex_exec_array(loc_conf->waf_verify_bot_bing_domain_regexp, &host, r->connection->log) == NGX_OK) {
        return NGX_HTTP_WAF_SUCCESS;
    }

    for (int i = 0; h->h_aliases[i] != NULL; i++) {
        host.data = (u_char*)h->h_aliases[i];
        host.len = strlen(h->h_aliases[i]);
        if (ngx_regex_exec_array(loc_conf->waf_verify_bot_bing_domain_regexp, &host, r->connection->log) == NGX_OK) {
            return NGX_HTTP_WAF_SUCCESS;
        }
    }

    return NGX_HTTP_WAF_FAKE_BOT;
}


static ngx_int_t _verify_baidu_spider(ngx_http_request_t* r) {
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, NULL);

    if (ngx_http_waf_check_flag(loc_conf->waf_verify_bot_type, NGX_HTTP_WAF_BAIDU_SPIDER) != NGX_HTTP_WAF_TRUE) {
        return NGX_HTTP_WAF_FAIL;
    }

    if (r->headers_in.user_agent->value.data == NULL || r->headers_in.user_agent->value.len == 0) {
        return NGX_HTTP_WAF_FAIL;
    }

    if (ngx_regex_exec_array(loc_conf->waf_verify_bot_baidu_ua_regexp,
                             &r->headers_in.user_agent->value,
                             r->connection->log) != NGX_OK) {
        return NGX_HTTP_WAF_FAIL;
    }

    struct hostent* h = NULL;
    if (r->connection->sockaddr->sa_family == AF_INET) {
        struct sockaddr_in* sin = (struct sockaddr_in*)r->connection->sockaddr;
        h = gethostbyaddr(&sin->sin_addr, sizeof(sin->sin_addr), AF_INET);
    }
#if (NGX_HAVE_INET6)
    else if (r->connection->sockaddr->sa_family == AF_INET6) {
        struct sockaddr_in6* sin6 = (struct sockaddr_in6*)r->connection->sockaddr;
        h = gethostbyaddr(&sin6->sin6_addr, sizeof(sin6->sin6_addr), AF_INET6);
    }
#endif

    if (h == NULL) {
        if (h_errno == HOST_NOT_FOUND) {
            return NGX_HTTP_WAF_FAKE_BOT;
        } else {
            return NGX_HTTP_WAF_FAIL;
        }
    }

    ngx_str_t host;
    host.data = (u_char*)h->h_name;
    host.len = strlen(h->h_name);
    if (ngx_regex_exec_array(loc_conf->waf_verify_bot_baidu_domain_regexp, &host, r->connection->log) == NGX_OK) {
        return NGX_HTTP_WAF_SUCCESS;
    }

    for (int i = 0; h->h_aliases[i] != NULL; i++) {
        host.data = (u_char*)h->h_aliases[i];
        host.len = strlen(h->h_aliases[i]);
        if (ngx_regex_exec_array(loc_conf->waf_verify_bot_baidu_domain_regexp, &host, r->connection->log) == NGX_OK) {
            return NGX_HTTP_WAF_SUCCESS;
        }
    }

    return NGX_HTTP_WAF_FAKE_BOT;
}

static ngx_int_t _verify_yandex_bot(ngx_http_request_t* r) {
    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, NULL);

    if (ngx_http_waf_check_flag(loc_conf->waf_verify_bot_type, NGX_HTTP_WAF_YANDEX_BOT) != NGX_HTTP_WAF_TRUE) {
        return NGX_HTTP_WAF_FAIL;
    }

    if (r->headers_in.user_agent->value.data == NULL || r->headers_in.user_agent->value.len == 0) {
        return NGX_HTTP_WAF_FAIL;
    }

    if (ngx_regex_exec_array(loc_conf->waf_verify_bot_yandex_ua_regexp,
                             &r->headers_in.user_agent->value,
                             r->connection->log) != NGX_OK) {
        return NGX_HTTP_WAF_FAIL;
    }

    struct hostent* h = NULL;
    if (r->connection->sockaddr->sa_family == AF_INET) {
        struct sockaddr_in* sin = (struct sockaddr_in*)r->connection->sockaddr;
        h = gethostbyaddr(&sin->sin_addr, sizeof(sin->sin_addr), AF_INET);
    }
#if (NGX_HAVE_INET6)
    else if (r->connection->sockaddr->sa_family == AF_INET6) {
        struct sockaddr_in6* sin6 = (struct sockaddr_in6*)r->connection->sockaddr;
        h = gethostbyaddr(&sin6->sin6_addr, sizeof(sin6->sin6_addr), AF_INET6);
    }
#endif

    if (h == NULL) {
        if (h_errno == HOST_NOT_FOUND) {
            return NGX_HTTP_WAF_FAKE_BOT;
        } else {
            return NGX_HTTP_WAF_FAIL;
        }
    }

    ngx_str_t host;
    host.data = (u_char*)h->h_name;
    host.len = strlen(h->h_name);
    if (ngx_regex_exec_array(loc_conf->waf_verify_bot_yandex_domain_regexp, &host, r->connection->log) == NGX_OK) {
        return NGX_HTTP_WAF_SUCCESS;
    }

    for (int i = 0; h->h_aliases[i] != NULL; i++) {
        host.data = (u_char*)h->h_aliases[i];
        host.len = strlen(h->h_aliases[i]);
        if (ngx_regex_exec_array(loc_conf->waf_verify_bot_yandex_domain_regexp, &host, r->connection->log) == NGX_OK) {
            return NGX_HTTP_WAF_SUCCESS;
        }
    }
    return NGX_HTTP_WAF_FAKE_BOT;
}

static ngx_int_t _gen_ctx(ngx_http_request_t* r, const char* detail) {
    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_get_ctx_and_conf(r, NULL, &ctx);

    ctx->blocked = NGX_HTTP_WAF_TRUE;
    strcpy((char*)(ctx->rule_type), "FAKE-BOT");
    strcpy((char*)(ctx->rule_deatils), detail);

    return NGX_HTTP_WAF_SUCCESS;
}