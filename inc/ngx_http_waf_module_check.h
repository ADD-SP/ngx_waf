/**
 * @file ngx_http_waf_module_check.h
 * @brief 检查诸如 IP，URL 等是否命中规则。
*/

#include <uthash.h>
#include <math.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_regex.h>
#include <ngx_inet.h>
#include <ngx_http_waf_module_macro.h>
#include <ngx_http_waf_module_type.h>
#include <ngx_http_waf_module_util.h>
#include <ngx_http_waf_module_ip_trie.h>
#include <ngx_http_waf_module_token_bucket_set.h>


#ifndef NGX_HTTP_WAF_MODLULE_CHECK_H
#define NGX_HTTP_WAF_MODLULE_CHECK_H

extern ngx_module_t ngx_http_waf_module; /**< 模块详情 */

/**
 * @defgroup check 规则匹配模块
 * @brief 检查诸如 IP，URL 等是否命中规则。
 * @addtogroup check 规则匹配模块
 * @{
*/

/**
 * @typedef ngx_http_waf_check
 * @brief 请求检查函数的函数指针
 * @param[out] out_http_status 当触发规则时需要返回的 HTTP 状态码。
*/
typedef ngx_int_t (*ngx_http_waf_check)(ngx_http_request_t* r, ngx_int_t* out_http_status);

/**
 * @brief 检查客户端 IP 地址是否在白名单中。
 * @param[out] out_http_status 当出发规则时需要返回的 HTTP 状态码。
 * @return 如果在返回 MATCHED，反之返回 NOT_MATCHED。
 * @retval MATCHED IP 地址在白名单中。
 * @retval NOT_MATCHED IP 地址不在白名单中。
*/
static ngx_int_t ngx_http_waf_handler_check_white_ip(ngx_http_request_t* r, ngx_int_t* out_http_status);


/**
 * @brief 检查客户端 IP 地址是否在黑名单中。
 * @param[out] out_http_status 当触发规则时需要返回的 HTTP 状态码。
 * @return 如果在返回 MATCHED，反之返回 NOT_MATCHED。
 * @retval MATCHED IP 地址在黑名单中。
 * @retval NOT_MATCHED IP 地址不在黑名单中。
*/
static ngx_int_t ngx_http_waf_handler_check_black_ip(ngx_http_request_t* r, ngx_int_t* out_http_status);


/**
 * @brief 检查客户端 IP 地址的访问频次（60 秒内）是否超出了限制。
 * @param[out] out_http_status 当触发规则时需要返回的 HTTP 状态码。
 * @return 如果超出 MATCHED，反之返回 NOT_MATCHED。
 * @retval MATCHED 超出限制。
 * @retval NOT_MATCHED 未超出限制。
*/
static ngx_int_t ngx_http_waf_handler_check_cc(ngx_http_request_t* r, ngx_int_t* out_http_status);


/**
 * @brief 检查 URL 是否在白名单中。
 * @param[out] out_http_status 当触发规则时需要返回的 HTTP 状态码。
 * @return 如果在返回 MATCHED，反之返回 NOT_MATCHED。
 * @retval MATCHED 在白名单中。
 * @retval NOT_MATCHED 不在白名单中
*/
static ngx_int_t ngx_http_waf_handler_check_white_url(ngx_http_request_t* r, ngx_int_t* out_http_status);


/**
 * @brief 检查 URL 是否在黑名单中
 * @param[out] out_http_status 当触发规则时需要返回的 HTTP 状态码。
 * @return 如果在返回 MATCHED，反之返回 NOT_MATCHED。
 * @retval MATCHED 在黑名单中。
 * @retval NOT_MATCHED 不在黑名单中
*/
static ngx_int_t ngx_http_waf_handler_check_black_url(ngx_http_request_t* r, ngx_int_t* out_http_status);


/**
 * @brief 检查请求参数是否在黑名单中
 * @param[out] out_http_status 当触发规则时需要返回的 HTTP 状态码。
 * @return 如果在返回 MATCHED，反之返回 NOT_MATCHED。
 * @retval MATCHED 在黑名单中。
 * @retval NOT_MATCHED 不在黑名单中
*/
static ngx_int_t ngx_http_waf_handler_check_black_args(ngx_http_request_t* r, ngx_int_t* out_http_status);


/**
 * @brief 检查 UserAgent 是否在黑名单中
 * @param[out] out_http_status 当触发规则时需要返回的 HTTP 状态码。
 * @return 如果在返回 MATCHED，反之返回 NOT_MATCHED。
 * @retval MATCHED 在黑名单中。
 * @retval NOT_MATCHED 不在黑名单中
*/
static ngx_int_t ngx_http_waf_handler_check_black_user_agent(ngx_http_request_t* r, ngx_int_t* out_http_status);


/**
 * @brief 检查 Referer 是否在白名单中
 * @param[out] out_http_status 当触发规则时需要返回的 HTTP 状态码。
 * @return 如果在返回 MATCHED，反之返回 NOT_MATCHED。
 * @retval MATCHED 在白名单中。
 * @retval NOT_MATCHED 不在白黑名单中
*/
static ngx_int_t ngx_http_waf_handler_check_white_referer(ngx_http_request_t* r, ngx_int_t* out_http_status);


/**
 * @brief 检查 Referer 是否在黑名单中
 * @param[out] out_http_status 当触发规则时需要返回的 HTTP 状态码。
 * @return 如果在返回 MATCHED，反之返回 NOT_MATCHED。
 * @retval MATCHED 在黑名单中。
 * @retval NOT_MATCHED 不在黑名单中
*/
static ngx_int_t ngx_http_waf_handler_check_black_referer(ngx_http_request_t* r, ngx_int_t* out_http_status);


/**
 * @brief 检查 Cookie 是否在黑名单中
 * @param[out] out_http_status 当触发规则时需要返回的 HTTP 状态码。
 * @return 如果在返回 MATCHED，反之返回 NOT_MATCHED。
 * @retval MATCHED 在黑名单中。
 * @retval NOT_MATCHED 不在黑名单中
*/
static ngx_int_t ngx_http_waf_handler_check_black_cookie(ngx_http_request_t* r, ngx_int_t* out_http_status);

/**
* @brief 检查请求体内容是否存在于黑名单中，存在则拦截，反之放行。
*/
static void check_post(ngx_http_request_t* r);

/**
 * @}
*/


static ngx_int_t ngx_http_waf_handler_check_white_ip(ngx_http_request_t* r, ngx_int_t* out_http_status) {
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);

    if (CHECK_FLAG(srv_conf->waf_mode, MODE_INSPECT_IP) == FALSE) {
        return NOT_MATCHED;
    }

    ip_trie_node_t* ip_trie_node = NULL;
    if (r->connection->sockaddr->sa_family == AF_INET) {
        struct sockaddr_in* sin = (struct sockaddr_in*)r->connection->sockaddr;
        inx_addr_t inx_addr;
        memcpy(&(inx_addr.ipv4), &(sin->sin_addr), sizeof(struct in_addr));
        if (ip_trie_find(srv_conf->white_ipv4, &inx_addr, &ip_trie_node) == SUCCESS) {
            ctx->blocked = FALSE;
            strcpy((char*)ctx->rule_type, "WHITE-IPV4");
            strcpy((char*)ctx->rule_deatils, (char*)ip_trie_node->text);
            *out_http_status = NGX_DECLINED;
            return MATCHED;
        }
    } else if (r->connection->sockaddr->sa_family == AF_INET6) {
        struct sockaddr_in6* sin6 = (struct sockaddr_in6*)r->connection->sockaddr;
        inx_addr_t inx_addr;
        
        memcpy(&(inx_addr.ipv6), &(sin6->sin6_addr), sizeof(struct in6_addr));
        if (ip_trie_find(srv_conf->white_ipv6, &inx_addr, &ip_trie_node) == SUCCESS) {
            ctx->blocked = FALSE;
            strcpy((char*)ctx->rule_type, "WHITE-IPV4");
            strcpy((char*)ctx->rule_deatils, (char*)ip_trie_node->text);
            *out_http_status = NGX_DECLINED;
            return MATCHED;
        }
    }

    return NOT_MATCHED;
}


static ngx_int_t ngx_http_waf_handler_check_black_ip(ngx_http_request_t* r, ngx_int_t* out_http_status) {
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);

    if (CHECK_FLAG(srv_conf->waf_mode, MODE_INSPECT_IP) == FALSE) {
        return NOT_MATCHED;
    }

    ip_trie_node_t *ip_trie_node = NULL;
    if (r->connection->sockaddr->sa_family == AF_INET) {
        struct sockaddr_in* sin = (struct sockaddr_in*)r->connection->sockaddr;
        inx_addr_t inx_addr;
        
        memcpy(&(inx_addr.ipv4), &(sin->sin_addr), sizeof(struct in_addr));
        if (ip_trie_find(srv_conf->black_ipv4, &inx_addr, &ip_trie_node) == SUCCESS) {
            ctx->blocked = FALSE;
            strcpy((char*)ctx->rule_type, "BLACK-IPV4");
            strcpy((char*)ctx->rule_deatils, (char*)ip_trie_node->text);
            *out_http_status = NGX_HTTP_FORBIDDEN;
            return MATCHED;
        }
    } else if (r->connection->sockaddr->sa_family == AF_INET6) {
        struct sockaddr_in6* sin6 = (struct sockaddr_in6*)r->connection->sockaddr;
        inx_addr_t inx_addr;
        memcpy(&(inx_addr.ipv6), &(sin6->sin6_addr), sizeof(struct in6_addr));
        if (ip_trie_find(srv_conf->black_ipv6, &inx_addr, &ip_trie_node) == SUCCESS) {
            ctx->blocked = FALSE;
            strcpy((char*)ctx->rule_type, "BLACK-IPV6");
            strcpy((char*)ctx->rule_deatils, (char*)ip_trie_node->text);
            *out_http_status = NGX_HTTP_FORBIDDEN;
            return MATCHED;
        }
    }

    return NOT_MATCHED;
}


static ngx_int_t ngx_http_waf_handler_check_cc(ngx_http_request_t* r, ngx_int_t* out_http_status) {
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);
    ngx_int_t ip_type = r->connection->sockaddr->sa_family;
    time_t now = time(NULL);
    
    if (CHECK_FLAG(srv_conf->waf_mode, MODE_INSPECT_CC) == FALSE) {
        return NOT_MATCHED;
    }
    if (srv_conf->waf_cc_deny_limit == NGX_CONF_UNSET
        || srv_conf->waf_cc_deny_duration == NGX_CONF_UNSET) {
        // ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_waf: CC-DENY-CONF-INVALID");
        return NOT_MATCHED;
    }

    inx_addr_t inx_addr;
    memset(&inx_addr, 0, sizeof(inx_addr_t));

    if (ip_type == AF_INET) {
        struct sockaddr_in* s_addr_in = (struct sockaddr_in*)(r->connection->sockaddr);
        memcpy(&(inx_addr.ipv4), &(s_addr_in->sin_addr), sizeof(struct in_addr));
    } else {
        struct sockaddr_in6* s_addr_in6 = (struct sockaddr_in6*)(r->connection->sockaddr);
        memcpy(&(inx_addr.ipv6), &(s_addr_in6->sin6_addr), sizeof(struct in6_addr));
    }

    ngx_slab_pool_t *shpool = (ngx_slab_pool_t *)srv_conf->shm_zone->shm.addr;
    ngx_shmtx_lock(&shpool->mutex);

    token_bucket_set_t* set = srv_conf->ip_token_bucket_set;
    double diff_put_minute = difftime(now, set->last_put) / 60;
    double diff_clear_minute = difftime(now, set->last_clear) / 60;

    if (diff_clear_minute > max(60, srv_conf->waf_cc_deny_duration * 5)) {
        token_bucket_set_clear(set);
        set->last_clear = now;
    } else if (diff_put_minute >= 1) {
        token_bucket_set_put(set, NULL, srv_conf->waf_cc_deny_limit, now);
        set->last_put = now;
    }


    
    if (token_bucket_set_take(set, &inx_addr, 1, now) != SUCCESS) {
        ctx->blocked = FALSE;
        strcpy((char*)ctx->rule_type, "CC-DNEY");
        strcpy((char*)ctx->rule_deatils, "");
        *out_http_status = NGX_HTTP_SERVICE_UNAVAILABLE;
        ngx_shmtx_unlock(&shpool->mutex);
        return MATCHED;
    }


    ngx_shmtx_unlock(&shpool->mutex);
    return NOT_MATCHED;
}


static ngx_int_t ngx_http_waf_handler_check_white_url(ngx_http_request_t* r, ngx_int_t* out_http_status) {
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);
    ngx_str_t* puri = &r->uri;
    ngx_regex_elt_t* p = srv_conf->white_url->elts;

    if (CHECK_FLAG(srv_conf->waf_mode, MODE_INSPECT_URL) == FALSE) {
        return NOT_MATCHED;
    }

    for (size_t i = 0; i < srv_conf->white_url->nelts; i++, p++) {
        ngx_int_t rc = ngx_regex_exec(p->regex, puri, NULL, 0);
        if (rc >= 0) {
            ctx->blocked = FALSE;
            strcpy((char*)ctx->rule_type, "WHITE-URL");
            strcpy((char*)ctx->rule_deatils, (char*)p->name);
            *out_http_status = NGX_DECLINED;
            return MATCHED;
        }
    }

    return NOT_MATCHED;
}


static ngx_int_t ngx_http_waf_handler_check_black_url(ngx_http_request_t* r, ngx_int_t* out_http_status) {
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);
    ngx_str_t* puri = &r->uri;
    ngx_regex_elt_t* p = srv_conf->black_url->elts;

    if (CHECK_FLAG(srv_conf->waf_mode, MODE_INSPECT_URL) == FALSE) {
        return NOT_MATCHED;
    }

    for (size_t i = 0; i < srv_conf->black_url->nelts; i++, p++) {
        ngx_int_t rc = ngx_regex_exec(p->regex, puri, NULL, 0);
        if (rc >= 0) {
            ctx->blocked = TRUE;
            strcpy((char*)ctx->rule_type, "BLACK-URL");
            strcpy((char*)ctx->rule_deatils, (char*)p->name);
            *out_http_status = NGX_HTTP_FORBIDDEN;
            return MATCHED;
        }
    }

    return NOT_MATCHED;
}


static ngx_int_t ngx_http_waf_handler_check_black_args(ngx_http_request_t* r, ngx_int_t* out_http_status) {
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);


    if (CHECK_FLAG(srv_conf->waf_mode, MODE_INSPECT_ARGS) == FALSE) {
        return NOT_MATCHED;
    }

    if (r->args.len == 0) {
        return NOT_MATCHED;
    }

    ngx_str_t* pargs = &r->args;
    ngx_regex_elt_t* p = srv_conf->black_args->elts;

    for (size_t i = 0; i < srv_conf->black_args->nelts; i++, p++) {
        ngx_int_t rc = ngx_regex_exec(p->regex, pargs, NULL, 0);
        if (rc >= 0) {
            ctx->blocked = TRUE;
            strcpy((char*)ctx->rule_type, "BLACK-ARGS");
            strcpy((char*)ctx->rule_deatils, (char*)p->name);
            *out_http_status = NGX_HTTP_FORBIDDEN;
            return MATCHED;
        }
    }

    return NOT_MATCHED;
}


static ngx_int_t ngx_http_waf_handler_check_black_user_agent(ngx_http_request_t* r, ngx_int_t* out_http_status) {
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);

    if (CHECK_FLAG(srv_conf->waf_mode, MODE_INSPECT_UA) == FALSE) {
        return NOT_MATCHED;
    }

    if (r->headers_in.user_agent == NULL) {
        return NOT_MATCHED;
    }

    ngx_str_t* pua = &r->headers_in.user_agent->value;
    ngx_regex_elt_t* p = srv_conf->black_ua->elts;

    for (size_t i = 0; i < srv_conf->black_ua->nelts; i++, p++) {
        ngx_int_t rc = ngx_regex_exec(p->regex, pua, NULL, 0);
        if (rc >= 0) {
            ctx->blocked = TRUE;
            strcpy((char*)ctx->rule_type, "BLACK-USER-AGENT");
            strcpy((char*)ctx->rule_deatils, (char*)p->name);
            *out_http_status = NGX_HTTP_FORBIDDEN;
            return MATCHED;
        }
    }

    return NOT_MATCHED;
}


static ngx_int_t ngx_http_waf_handler_check_white_referer(ngx_http_request_t* r, ngx_int_t* out_http_status) {
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);

    if (CHECK_FLAG(srv_conf->waf_mode, MODE_INSPECT_REFERER) == FALSE) {
        return NOT_MATCHED;
    }

    if (r->headers_in.referer == NULL) {
        return NOT_MATCHED;
    }

    ngx_str_t* preferer = &r->headers_in.referer->value;
    ngx_regex_elt_t* p = srv_conf->white_referer->elts;

    for (size_t i = 0; i < srv_conf->white_referer->nelts; i++, p++) {
        ngx_int_t rc = ngx_regex_exec(p->regex, preferer, NULL, 0);
        if (rc >= 0) {
            ctx->blocked = FALSE;
            strcpy((char*)ctx->rule_type, "WHITE-REFERER");
            strcpy((char*)ctx->rule_deatils, (char*)p->name);
            *out_http_status = NGX_DECLINED;
            return MATCHED;
        }
    }

    return NOT_MATCHED;
}


static ngx_int_t ngx_http_waf_handler_check_black_referer(ngx_http_request_t* r, ngx_int_t* out_http_status) {
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);

    if (CHECK_FLAG(srv_conf->waf_mode, MODE_INSPECT_REFERER) == FALSE) {
        return NOT_MATCHED;
    }

    if (r->headers_in.referer == NULL) {
        return NOT_MATCHED;
    }

    ngx_str_t* preferer = &r->headers_in.referer->value;
    ngx_regex_elt_t* p = srv_conf->black_referer->elts;

    for (size_t i = 0; i < srv_conf->black_referer->nelts; i++, p++) {
        ngx_int_t rc = ngx_regex_exec(p->regex, preferer, NULL, 0);
        if (rc >= 0) {
            ctx->blocked = FALSE;
            strcpy((char*)ctx->rule_type, "BLACK-REFERER");
            strcpy((char*)ctx->rule_deatils, (char*)p->name);
            *out_http_status = NGX_HTTP_FORBIDDEN;
            return MATCHED;
        }
    }

    return NOT_MATCHED;
}


static ngx_int_t ngx_http_waf_handler_check_black_cookie(ngx_http_request_t* r, ngx_int_t* out_http_status) {
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);

    if (CHECK_FLAG(srv_conf->waf_mode, MODE_INSPECT_COOKIE) == FALSE) {
        return NOT_MATCHED;
    }

    if (r->headers_in.cookies.nelts != 0) {
        ngx_table_elt_t** ppcookie = r->headers_in.cookies.elts;
        for (size_t i = 0; i < r->headers_in.cookies.nelts; i++, ppcookie++) {
            ngx_regex_elt_t* p = srv_conf->black_cookie->elts;
            for (size_t j = 0; j < srv_conf->black_cookie->nelts; j++, p++) {
                ngx_int_t rc = ngx_regex_exec(p->regex, &((*ppcookie)->value), NULL, 0);
                if (rc >= 0) {
                    ctx->blocked = TRUE;
                    strcpy((char*)ctx->rule_type, "BLACK-COOKIE");
                    strcpy((char*)ctx->rule_deatils, (char*)p->name);
                    *out_http_status = NGX_HTTP_FORBIDDEN;
                    return MATCHED;
                }

                rc = ngx_regex_exec(p->regex, &((*ppcookie)->key), NULL, 0);
                if (rc >= 0) {
                    ctx->blocked = TRUE;
                    strcpy((char*)ctx->rule_type, "BLACK-COOKIE");
                    strcpy((char*)ctx->rule_deatils, (char*)p->name);
                    *out_http_status = NGX_HTTP_FORBIDDEN;
                    return MATCHED;
                }
            }
        }
    }

    return NOT_MATCHED;
}


static void check_post(ngx_http_request_t* r) {
    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);
    ngx_chain_t* buf_chain = r->request_body == NULL ? NULL : r->request_body->bufs;
    ngx_buf_t* body_buf = NULL;
    ngx_str_t body_str;

    ctx->read_body_done = TRUE;

    while (buf_chain != NULL) {
        body_buf = buf_chain->buf;

        if (body_buf == NULL) {
            break;
        }

        body_str.data = body_buf->pos;
        body_str.len = body_buf->last - body_buf->pos;


        if (!ngx_buf_in_memory(body_buf)) {
            buf_chain = buf_chain->next;
            continue;
        }

        ngx_regex_elt_t* p = srv_conf->black_post->elts;
        ngx_int_t rc;
        for (size_t i = 0; i < srv_conf->black_post->nelts; i++, p++) {
            rc = ngx_regex_exec(p->regex, &body_str, NULL, 0);
            if (rc >= 0) {
                ctx->blocked = TRUE;
                strcpy((char*)ctx->rule_type, "BLACK-POST");
                strcpy((char*)ctx->rule_deatils, (char*)p->name);
                ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "ngx_waf: [%s][%s]", ctx->rule_type, ctx->rule_deatils);
                ngx_http_finalize_request(r, NGX_HTTP_FORBIDDEN);
                return;
            }
        }
        buf_chain = buf_chain->next;
    }
    ngx_http_finalize_request(r, NGX_DONE);
    ngx_http_core_run_phases(r);
}


#endif
