#include <ngx_http_waf_module_verify_bot.h>

static ngx_int_t _verify_google_bot(ngx_http_request_t* r);

static ngx_int_t _verify_bing_bot(ngx_http_request_t* r);

static ngx_int_t _verify_baidu_spider(ngx_http_request_t* r);

static ngx_int_t _verify_yandex_bot(ngx_http_request_t* r);

static ngx_int_t _verify_sogou_spider(ngx_http_request_t* r);

static ngx_int_t _verify_by_rdns(ngx_http_request_t* r, ngx_array_t* ua_regex, ngx_array_t* domain_regex);

// static ngx_int_t _gen_ctx(ngx_http_request_t* r, const char* detail);

ngx_int_t ngx_http_waf_handler_verify_bot(ngx_http_request_t* r) {
    ngx_http_waf_dp_func_start(r);

    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, NULL);

    if (ngx_http_waf_is_unset_or_disable_value(loc_conf->waf_verify_bot)) {
        ngx_http_waf_dp(r, "nothing to do ... return");
        return NGX_HTTP_WAF_NOT_MATCHED;
    }

    action_t* action_internal_err = ngx_pcalloc(r->pool, sizeof(action_t));
    ngx_http_waf_set_action_return(action_internal_err, NGX_HTTP_INTERNAL_SERVER_ERROR, ACTION_FLAG_FROM_CAPTCHA);

    action_t* action_decline = ngx_pcalloc(r->pool, sizeof(action_t));
    ngx_http_waf_set_action_decline(action_decline, ACTION_FLAG_FROM_CAPTCHA);

    action_t* action = NULL;
    ngx_http_waf_copy_action_chain(r->pool, action, loc_conf->action_chain_verify_bot);

    #define ngx_http_waf_func(handler, bot) {                                   \
        ngx_http_waf_dpf(r, "verfiying %s", bot);                               \
        ngx_int_t rc = (handler)(r);                                            \
        if (rc == NGX_HTTP_WAF_FAKE_BOT && loc_conf->waf_verify_bot == 2) {     \
            ngx_http_waf_dp(r, "fake bot ... return");                          \
            ngx_http_waf_append_action_chain(r, action);                        \
            return NGX_HTTP_WAF_MATCHED;                                        \
        } else if (rc == NGX_HTTP_WAF_SUCCESS) {                                \
            ngx_http_waf_dp(r, "real bot ... return");                          \
            ngx_http_waf_append_action_chain(r, action_decline);                \
            ngx_http_waf_set_rule_info(r, "FAKE-BOT", bot,                      \
                NGX_HTTP_WAF_TRUE, NGX_HTTP_WAF_TRUE);                          \
            return NGX_HTTP_WAF_MATCHED;                                        \
        }                                                                       \
    }

    ngx_http_waf_func(_verify_google_bot, "GoogleBot");
    ngx_http_waf_func(_verify_bing_bot, "BingBot");
    ngx_http_waf_func(_verify_baidu_spider, "BaiduSpider");
    ngx_http_waf_func(_verify_yandex_bot, "YandexBot");
    ngx_http_waf_func(_verify_sogou_spider, "SogouSpider");

    #undef ngx_http_waf_func

    ngx_http_waf_dp_func_end(r);
    return NGX_HTTP_WAF_NOT_MATCHED;
}


static ngx_int_t _verify_google_bot(ngx_http_request_t* r) {
    ngx_http_waf_dp_func_start(r);

    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, NULL);

    if (!ngx_http_waf_check_flag(loc_conf->waf_verify_bot_type, BOT_TYPE_GOOGLE)) {
        return NGX_HTTP_WAF_FAIL;
    }

    ngx_int_t rc = _verify_by_rdns(r, 
        loc_conf->waf_verify_bot_google_ua_regexp, 
        loc_conf->waf_verify_bot_google_domain_regexp);

    ngx_http_waf_dp_func_end(r);
    return rc;
}


static ngx_int_t _verify_bing_bot(ngx_http_request_t* r) {
    ngx_http_waf_dp_func_start(r);

    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, NULL);

    if (!ngx_http_waf_check_flag(loc_conf->waf_verify_bot_type, BOT_TYPE_BING)) {
        return NGX_HTTP_WAF_FAIL;
    }

    ngx_int_t rc = _verify_by_rdns(r, 
        loc_conf->waf_verify_bot_bing_ua_regexp, 
        loc_conf->waf_verify_bot_bing_domain_regexp);

    ngx_http_waf_dp_func_end(r);
    return rc;
}


static ngx_int_t _verify_baidu_spider(ngx_http_request_t* r) {
    ngx_http_waf_dp_func_start(r);

    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, NULL);

    if (!ngx_http_waf_check_flag(loc_conf->waf_verify_bot_type, BOT_TYPE_BAIDU)) {
        return NGX_HTTP_WAF_FAIL;
    }

    ngx_int_t rc = _verify_by_rdns(r, 
        loc_conf->waf_verify_bot_baidu_ua_regexp,
        loc_conf->waf_verify_bot_baidu_domain_regexp);

    ngx_http_waf_dp_func_end(r);
    return rc;
}

static ngx_int_t _verify_yandex_bot(ngx_http_request_t* r) {
    ngx_http_waf_dp_func_start(r);

    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, NULL);

    if (!ngx_http_waf_check_flag(loc_conf->waf_verify_bot_type, BOT_TYPE_YANDEX)) {
        return NGX_HTTP_WAF_FAIL;
    }

    ngx_int_t rc = _verify_by_rdns(r, 
        loc_conf->waf_verify_bot_yandex_ua_regexp,
        loc_conf->waf_verify_bot_yandex_domain_regexp);

    ngx_http_waf_dp_func_end(r);
    return rc;
}

static ngx_int_t _verify_sogou_spider(ngx_http_request_t* r) {
    ngx_http_waf_dp_func_start(r);

    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, NULL);

    if (!ngx_http_waf_check_flag(loc_conf->waf_verify_bot_type, BOT_TYPE_SOGOU)) {
        return NGX_HTTP_WAF_FAIL;
    }

    ngx_int_t rc = _verify_by_rdns(r, 
        loc_conf->waf_verify_bot_sogou_ua_regexp,
        loc_conf->waf_verify_bot_sogou_domain_regexp);

    ngx_http_waf_dp_func_end(r);
    return rc;
}


static ngx_int_t _verify_by_rdns(ngx_http_request_t* r, ngx_array_t* ua_regex, ngx_array_t* domain_regex) {
    ngx_http_waf_dp_func_start(r);

    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, NULL);

    if (r->headers_in.user_agent == NULL) {
        ngx_http_waf_dp(r, "no user-agent");
        return NGX_HTTP_WAF_FAIL;
    }

    if (r->headers_in.user_agent->value.data == NULL || r->headers_in.user_agent->value.len == 0) {
        ngx_http_waf_dp(r, "no user-agent");
        return NGX_HTTP_WAF_FAIL;
    }

    ngx_http_waf_dpf(r, "verifying user-agent %V", &r->headers_in.user_agent->value);
    if (ngx_regex_exec_array(ua_regex,
                             &r->headers_in.user_agent->value,
                             r->connection->log) != NGX_OK) {
        ngx_http_waf_dp(r, "failed ... return");
        return NGX_HTTP_WAF_FAIL;
    }
    ngx_http_waf_dp(r, "success");

    ngx_http_waf_dp(r, "getting client's host");
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
            ngx_http_waf_dp(r, "host not found");
            ngx_http_waf_dp(r, "fake bot ... return");
            return NGX_HTTP_WAF_FAKE_BOT;
        } else {
            ngx_http_waf_dp(r, "failed ... return");
            return NGX_HTTP_WAF_FAIL;
        }
    }

    ngx_http_waf_dp(r, "success");

    ngx_str_t host;
    host.data = (u_char*)h->h_name;
    host.len = ngx_strlen(h->h_name);
    ngx_http_waf_dpf(r, "verifying host %V", &host);
    if (ngx_regex_exec_array(domain_regex, &host, r->connection->log) == NGX_OK) {
        ngx_http_waf_dp(r, "success ... return");
        return NGX_HTTP_WAF_SUCCESS;
    }

    for (int i = 0; h->h_aliases[i] != NULL; i++) {
        host.data = (u_char*)h->h_aliases[i];
        host.len = ngx_strlen(h->h_aliases[i]);
        ngx_http_waf_dpf(r, "verifying host %V", &host);
        if (ngx_regex_exec_array(domain_regex, &host, r->connection->log) == NGX_OK) {
            ngx_http_waf_dp(r, "success ... return");
            return NGX_HTTP_WAF_SUCCESS;
        }
    }

    ngx_http_waf_dp(r, "fake bot");
    ngx_http_waf_dp_func_end(r);
    return NGX_HTTP_WAF_FAKE_BOT;
}