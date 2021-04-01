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
#include <ngx_http_waf_module_lru_cache.h>
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
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: Start inspecting the IP whitelist.");

    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: The module context has been obtained.");

    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: The configuration of the module has been obtained.");

    ngx_int_t ret_value = NOT_MATCHED;

    if (CHECK_FLAG(srv_conf->waf_mode, MODE_INSPECT_IP) == FALSE) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Because this Inspection is disabled in the configuration, no Inspection is performed.");
        ret_value = NOT_MATCHED;
    } else if (CHECK_FLAG(srv_conf->waf_mode, r->method) == FALSE) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Because this Http.Method is disabled in the configuration, no Inspection is performed.");
        ret_value = NOT_MATCHED;
    } else {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Inspection has begun.");

        ip_trie_node_t* ip_trie_node = NULL;
        if (r->connection->sockaddr->sa_family == AF_INET) {
            struct sockaddr_in* sin = (struct sockaddr_in*)r->connection->sockaddr;
            inx_addr_t inx_addr;
            ngx_memcpy(&(inx_addr.ipv4), &(sin->sin_addr), sizeof(struct in_addr));
            if (ip_trie_find(&srv_conf->white_ipv4, &inx_addr, &ip_trie_node) == SUCCESS) {
                ctx->blocked = FALSE;
                strcpy((char*)ctx->rule_type, "WHITE-IPV4");
                strcpy((char*)ctx->rule_deatils, (char*)ip_trie_node->text);
                *out_http_status = NGX_DECLINED;
                ret_value = MATCHED;
            }
        } else if (r->connection->sockaddr->sa_family == AF_INET6) {
            struct sockaddr_in6* sin6 = (struct sockaddr_in6*)r->connection->sockaddr;
            inx_addr_t inx_addr;
            
            ngx_memcpy(&(inx_addr.ipv6), &(sin6->sin6_addr), sizeof(struct in6_addr));
            if (ip_trie_find(&srv_conf->white_ipv6, &inx_addr, &ip_trie_node) == SUCCESS) {
                ctx->blocked = FALSE;
                strcpy((char*)ctx->rule_type, "WHITE-IPV4");
                strcpy((char*)ctx->rule_deatils, (char*)ip_trie_node->text);
                *out_http_status = NGX_DECLINED;
                ret_value = MATCHED;
            }
        }

        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Inspection is over.");
    }

    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: The IP whitelist inspection process is fully completed.");
    return ret_value;
}


static ngx_int_t ngx_http_waf_handler_check_black_ip(ngx_http_request_t* r, ngx_int_t* out_http_status) {
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: Start inspecting the IP blacklist.");

    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: The module context has been obtained.");

    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: The configuration of the module has been obtained.");
    
    ngx_int_t ret_value = NOT_MATCHED;

    if (CHECK_FLAG(srv_conf->waf_mode, MODE_INSPECT_IP) == FALSE) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Because this Inspection is disabled in the configuration, no Inspection is performed.");
        ret_value = NOT_MATCHED;
    } else if (CHECK_FLAG(srv_conf->waf_mode, r->method) == FALSE) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Because this Http.Method is disabled in the configuration, no Inspection is performed.");
        ret_value = NOT_MATCHED;
    } else {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Inspection has begun.");

        ip_trie_node_t *ip_trie_node = NULL;
        if (r->connection->sockaddr->sa_family == AF_INET) {
            struct sockaddr_in* sin = (struct sockaddr_in*)r->connection->sockaddr;
            inx_addr_t inx_addr;
            
            ngx_memcpy(&(inx_addr.ipv4), &(sin->sin_addr), sizeof(struct in_addr));
            if (ip_trie_find(&srv_conf->black_ipv4, &inx_addr, &ip_trie_node) == SUCCESS) {
                ctx->blocked = TRUE;
                strcpy((char*)ctx->rule_type, "BLACK-IPV4");
                strcpy((char*)ctx->rule_deatils, (char*)ip_trie_node->text);
                *out_http_status = NGX_HTTP_FORBIDDEN;
                ret_value = MATCHED;
            }
        } else if (r->connection->sockaddr->sa_family == AF_INET6) {
            struct sockaddr_in6* sin6 = (struct sockaddr_in6*)r->connection->sockaddr;
            inx_addr_t inx_addr;
            ngx_memcpy(&(inx_addr.ipv6), &(sin6->sin6_addr), sizeof(struct in6_addr));
            if (ip_trie_find(&srv_conf->black_ipv6, &inx_addr, &ip_trie_node) == SUCCESS) {
                ctx->blocked = TRUE;
                strcpy((char*)ctx->rule_type, "BLACK-IPV6");
                strcpy((char*)ctx->rule_deatils, (char*)ip_trie_node->text);
                *out_http_status = NGX_HTTP_FORBIDDEN;
                ret_value = MATCHED;
            }
        }

        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Inspection is over.");
    }

    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: The IP blacklist inspection process is fully completed.");
    return ret_value;
}


static ngx_int_t ngx_http_waf_handler_check_cc(ngx_http_request_t* r, ngx_int_t* out_http_status) {
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: Start the CC inspection process.");

    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: The module context has been obtained.");

    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: The configuration of the module has been obtained.");
    
    ngx_int_t ret_value = NOT_MATCHED;
    ngx_int_t ip_type = r->connection->sockaddr->sa_family;
    time_t now = time(NULL);
    
    if (CHECK_FLAG(srv_conf->waf_mode, MODE_INSPECT_CC) == FALSE) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Because this detection is disabled in the configuration, no detection is performed.");
        ret_value = NOT_MATCHED;
    } else if (srv_conf->waf_cc_deny_limit == NGX_CONF_UNSET
        || srv_conf->waf_cc_deny_duration == NGX_CONF_UNSET) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Because this detection is disabled in the configuration, no detection is performed.");
        ret_value = NOT_MATCHED;
    } else {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Detection has begun.");

        inx_addr_t inx_addr;
        ngx_memset(&inx_addr, 0, sizeof(inx_addr_t));

        if (ip_type == AF_INET) {
            struct sockaddr_in* s_addr_in = (struct sockaddr_in*)(r->connection->sockaddr);
            ngx_memcpy(&(inx_addr.ipv4), &(s_addr_in->sin_addr), sizeof(struct in_addr));
        } else {
            struct sockaddr_in6* s_addr_in6 = (struct sockaddr_in6*)(r->connection->sockaddr);
            ngx_memcpy(&(inx_addr.ipv6), &(s_addr_in6->sin6_addr), sizeof(struct in6_addr));
        }

        // ngx_slab_pool_t *shpool = (ngx_slab_pool_t *)srv_conf->shm_zone_cc_deny->shm.addr;

        // ngx_shmtx_lock(&shpool->mutex);
        // ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        //     "ngx_waf_debug: Shared memory is locked.");

        token_bucket_set_t* set = &srv_conf->ip_token_bucket_set;
        double diff_put_minute = difftime(now, set->last_put) / 60;

        if (diff_put_minute >= 1) {
            if (token_bucket_set_put(set, NULL, srv_conf->waf_cc_deny_limit, now) != SUCCESS) {
                ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
                    "ngx_waf_debug: Failed to add tokens to the token bucket.");
            }
            set->last_put = now;
        }

        switch (token_bucket_set_take(set, &inx_addr, 1, now)) {
            case MALLOC_ERROR:
                ngx_log_error(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
                    "ngx_waf_debug: Unable to allocate shared memory.");
                ngx_post_event(&(srv_conf->event_clear_token_bucket_set), &ngx_posted_events);
                ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
                    "ngx_waf_debug: Trigger event - token_bucket_set.clear .");
                break;
            case FAIL:
                ctx->blocked = TRUE;
                strcpy((char*)ctx->rule_type, "CC-DNEY");
                strcpy((char*)ctx->rule_deatils, "");
                *out_http_status = NGX_HTTP_SERVICE_UNAVAILABLE;
                ret_value = MATCHED;
                break;
            case SUCCESS:
                break;
        }
        
        // ngx_shmtx_unlock(&shpool->mutex);
        // ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        //     "ngx_waf_debug: Shared memory is unlocked.");

        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Detection is over.");

    }

    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: The CC detection process is fully completed.");
    return ret_value;
}


static ngx_int_t ngx_http_waf_handler_check_white_url(ngx_http_request_t* r, ngx_int_t* out_http_status) {
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: Start inspecting the URL whitelist.");

    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: The module context has been obtained.");

    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: The configuration of the module has been obtained.");

    ngx_int_t ret_value = NOT_MATCHED;

    if (CHECK_FLAG(srv_conf->waf_mode, MODE_INSPECT_URL) == FALSE) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Because this detection is disabled in the configuration, no detection is performed.");
        ret_value = NOT_MATCHED;
    } else if (CHECK_FLAG(srv_conf->waf_mode, r->method) == FALSE) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Because this Http.Method is disabled in the configuration, no Inspection is performed.");
        ret_value = NOT_MATCHED;
    } else {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Inspection has begun.");

        ngx_str_t* p_uri = &r->uri;
        ngx_regex_elt_t* p = srv_conf->white_url->elts;


        if (p_uri->data == NULL || p_uri->len == 0) {
            ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: The Inspection is skipped because the URL is empty.");
            ret_value = NOT_MATCHED;
        } else {
            u_char* rule_details = NULL;
            ngx_int_t cache_hit = FAIL;
            if (CHECK_FLAG(srv_conf->waf_mode, MODE_EXTRA_CACHE) == TRUE) {
                cache_hit = lru_cache_manager_find(&srv_conf->white_url_inspection_cache, 
                                                    p_uri->data, 
                                                    p_uri->len, 
                                                    &ret_value, 
                                                    &rule_details);
            }

            if (cache_hit != SUCCESS) {
                for (size_t i = 0; i < srv_conf->white_url->nelts; i++, p++) {
                    ngx_int_t rc = ngx_regex_exec(p->regex, p_uri, NULL, 0);
                    if (rc >= 0) {
                        ret_value = MATCHED;
                        rule_details = p->name;
                        break;
                    }
                }
            }

            if (CHECK_FLAG(srv_conf->waf_mode, MODE_EXTRA_CACHE) == TRUE) {
                lru_cache_manager_add(&srv_conf->white_url_inspection_cache, 
                                        p_uri->data, 
                                        p_uri->len, 
                                        ret_value, 
                                        rule_details);
            }

            if (ret_value == MATCHED) {
                ctx->blocked = FALSE;
                strcpy((char*)ctx->rule_type, "WHITE-URL");
                strcpy((char*)ctx->rule_deatils, (char*)rule_details);
                *out_http_status = NGX_DECLINED;
            }
        }

        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Inspection is over.");
    }

    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: The URL whitelist inspection process is fully completed.");
    return ret_value;
}


static ngx_int_t ngx_http_waf_handler_check_black_url(ngx_http_request_t* r, ngx_int_t* out_http_status) {
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: Start inspecting the URL blacklist.");

    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: The module context has been obtained.");

    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: The configuration of the module has been obtained.");

    ngx_int_t ret_value = NOT_MATCHED;

    if (CHECK_FLAG(srv_conf->waf_mode, MODE_INSPECT_URL) == FALSE) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Because this Inspection is disabled in the configuration, no Inspection is performed.");
        ret_value = NOT_MATCHED;
    } else if (CHECK_FLAG(srv_conf->waf_mode, r->method) == FALSE) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Because this Http.Method is disabled in the configuration, no Inspection is performed.");
        ret_value = NOT_MATCHED;
    } else {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Inspection has begun.");

        ngx_str_t* p_uri = &r->uri;
        ngx_regex_elt_t* p = srv_conf->black_url->elts;

        if (p_uri->data == NULL || p_uri->len == 0) {
            ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: The Inspection is skipped because the URL is empty.");
            ret_value = NOT_MATCHED;
        } else {
            u_char* rule_details = NULL;
            ngx_int_t cache_hit = FAIL;
            if (CHECK_FLAG(srv_conf->waf_mode, MODE_EXTRA_CACHE) == TRUE) {
                cache_hit = lru_cache_manager_find(&srv_conf->black_url_inspection_cache, 
                                                    p_uri->data, 
                                                    p_uri->len, 
                                                    &ret_value, 
                                                    &rule_details);
            }

            if (cache_hit != SUCCESS) {
                for (size_t i = 0; i < srv_conf->black_url->nelts; i++, p++) {
                    ngx_int_t rc = ngx_regex_exec(p->regex, p_uri, NULL, 0);
                    if (rc >= 0) {
                        ret_value = MATCHED;
                        rule_details = p->name;
                        break;
                    }
                }
            }

            if (CHECK_FLAG(srv_conf->waf_mode, MODE_EXTRA_CACHE) == TRUE) {
                lru_cache_manager_add(&srv_conf->black_url_inspection_cache, 
                                        p_uri->data, 
                                        p_uri->len, 
                                        ret_value, 
                                        rule_details);
            }

            if (ret_value == MATCHED) {
                ctx->blocked = TRUE;
                strcpy((char*)ctx->rule_type, "BLACK-URL");
                strcpy((char*)ctx->rule_deatils, (char*)rule_details);
                *out_http_status = NGX_HTTP_FORBIDDEN;
            }
        }

        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Inspection is over.");
    }

    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: The URL blacklist inspection process is fully completed.");
    return ret_value;
}


static ngx_int_t ngx_http_waf_handler_check_black_args(ngx_http_request_t* r, ngx_int_t* out_http_status) {
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: Start inspecting the ARGS blacklist.");

    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: The module context has been obtained.");

    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: The configuration of the module has been obtained.");

    ngx_int_t ret_value = NOT_MATCHED;

    if (CHECK_FLAG(srv_conf->waf_mode, MODE_INSPECT_ARGS) == FALSE) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Because this Inspection is disabled in the configuration, no Inspection is performed.");
        ret_value = NOT_MATCHED;
    } else if (CHECK_FLAG(srv_conf->waf_mode, r->method) == FALSE) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Because this Http.Method is disabled in the configuration, no Inspection is performed.");
        ret_value = NOT_MATCHED;
    } else if (r->args.len == 0) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: The Inspection is skipped because the ARGS is empty.");
        ret_value = NOT_MATCHED;
    } else {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Inspection has begun.");

        ngx_str_t* p_args = &r->args;
        ngx_regex_elt_t* p = srv_conf->black_args->elts;


        if (p_args->data == NULL || p_args->len == 0) {
            ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: The Inspection is skipped because the ARGS is empty.");
            ret_value = NOT_MATCHED;
        } else {
            u_char* rule_details = NULL;
            ngx_int_t cache_hit = FAIL;
            if (CHECK_FLAG(srv_conf->waf_mode, MODE_EXTRA_CACHE) == TRUE) {
                cache_hit = lru_cache_manager_find(&srv_conf->black_args_inspection_cache, 
                                                    p_args->data, 
                                                    p_args->len, 
                                                    &ret_value, 
                                                    &rule_details);
            }

            if (cache_hit != SUCCESS) {
                for (size_t i = 0; i < srv_conf->black_args->nelts; i++, p++) {
                    ngx_int_t rc = ngx_regex_exec(p->regex, p_args, NULL, 0);
                    if (rc >= 0) {
                        ret_value = MATCHED;
                        rule_details = p->name;
                        break;
                    }
                }
            }

            if (CHECK_FLAG(srv_conf->waf_mode, MODE_EXTRA_CACHE) == TRUE) {
                lru_cache_manager_add(&srv_conf->black_args_inspection_cache, 
                                        p_args->data, 
                                        p_args->len, 
                                        ret_value, 
                                        rule_details);
            }

            if (ret_value == MATCHED) {
                ctx->blocked = TRUE;
                strcpy((char*)ctx->rule_type, "BLACK-ARGS");
                strcpy((char*)ctx->rule_deatils, (char*)rule_details);
                *out_http_status = NGX_HTTP_FORBIDDEN;
            }
        }

        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Inspection is over.");
    }

    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: The ARGS blacklist inspection process is fully completed.");
    return ret_value;
}


static ngx_int_t ngx_http_waf_handler_check_black_user_agent(ngx_http_request_t* r, ngx_int_t* out_http_status) {
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: Start inspecting the User-Agent blacklist.");

    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: The module context has been obtained.");

    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: The configuration of the module has been obtained.");

    ngx_int_t ret_value = NOT_MATCHED;

    if (CHECK_FLAG(srv_conf->waf_mode, MODE_INSPECT_UA) == FALSE) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Because this Inspection is disabled in the configuration, no Inspection is performed.");
        ret_value = NOT_MATCHED;
    } else if (CHECK_FLAG(srv_conf->waf_mode, r->method) == FALSE) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Because this Http.Method is disabled in the configuration, no Inspection is performed.");
        ret_value = NOT_MATCHED;
    } else if (r->headers_in.user_agent == NULL) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: The Inspection is skipped because the User-Agent is empty.");
        ret_value = NOT_MATCHED;
    } else {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Inspection has begun.");

        ngx_str_t* p_ua = &r->headers_in.user_agent->value;
        ngx_regex_elt_t* p = srv_conf->black_ua->elts;


        if (p_ua->data == NULL || p_ua->len == 0) {
            ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: The Inspection is skipped because the User-Agent is empty.");
            ret_value = NOT_MATCHED;
        } else {
            u_char* rule_details = NULL;
            ngx_int_t cache_hit = FAIL;
            if (CHECK_FLAG(srv_conf->waf_mode, MODE_EXTRA_CACHE) == TRUE) {
                cache_hit = lru_cache_manager_find(&srv_conf->black_ua_inspection_cache, 
                                                    p_ua->data, 
                                                    p_ua->len, 
                                                    &ret_value, 
                                                    &rule_details);
            }

            if (cache_hit != SUCCESS) {
                for (size_t i = 0; i < srv_conf->black_ua->nelts; i++, p++) {
                    ngx_int_t rc = ngx_regex_exec(p->regex, p_ua, NULL, 0);
                    if (rc >= 0) {
                        ret_value = MATCHED;
                        rule_details = p->name;
                        break;
                    }
                }
            }

            if (CHECK_FLAG(srv_conf->waf_mode, MODE_EXTRA_CACHE) == TRUE) {
                lru_cache_manager_add(&srv_conf->black_ua_inspection_cache, 
                                        p_ua->data, 
                                        p_ua->len, 
                                        ret_value, 
                                        rule_details);
            }

            if (ret_value == MATCHED) {
                ctx->blocked = TRUE;
                strcpy((char*)ctx->rule_type, "BLACK-USER-AGENT");
                strcpy((char*)ctx->rule_deatils, (char*)rule_details);
                *out_http_status = NGX_HTTP_FORBIDDEN;
            }
        }

        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Inspection is over.");
    }

    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: The User-Agent blacklist inspection process is fully completed.");
    return ret_value;
}


static ngx_int_t ngx_http_waf_handler_check_white_referer(ngx_http_request_t* r, ngx_int_t* out_http_status) {
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: Start inspecting the Referer whitelist.");

    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: The module context has been obtained.");

    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: The configuration of the module has been obtained.");

    ngx_int_t ret_value = NOT_MATCHED;

    if (CHECK_FLAG(srv_conf->waf_mode, MODE_INSPECT_REFERER) == FALSE) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Because this Inspection is disabled in the configuration, no Inspection is performed.");
        ret_value = NOT_MATCHED;
    } else if (CHECK_FLAG(srv_conf->waf_mode, r->method) == FALSE) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Because this Http.Method is disabled in the configuration, no Inspection is performed.");
        ret_value = NOT_MATCHED;
    } else if (r->headers_in.referer == NULL) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: The Inspection is skipped because the Referer is empty.");
        ret_value = NOT_MATCHED;
    } else {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Inspection has begun.");

        ngx_str_t* p_referer = &r->headers_in.referer->value;
        ngx_regex_elt_t* p = srv_conf->white_referer->elts;


        if (p_referer->data == NULL || p_referer->len == 0) {
            ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: The Inspection is skipped because the Referer is empty.");
            ret_value = NOT_MATCHED;
        } else {
            u_char* rule_details = NULL;
            ngx_int_t cache_hit = FAIL;
            if (CHECK_FLAG(srv_conf->waf_mode, MODE_EXTRA_CACHE) == TRUE) {
                cache_hit = lru_cache_manager_find(&srv_conf->white_referer_inspection_cache, 
                                                    p_referer->data, 
                                                    p_referer->len, 
                                                    &ret_value, 
                                                    &rule_details);
            }

            if (cache_hit != SUCCESS) {
                for (size_t i = 0; i < srv_conf->white_referer->nelts; i++, p++) {
                    ngx_int_t rc = ngx_regex_exec(p->regex, p_referer, NULL, 0);
                    if (rc >= 0) {
                        ret_value = MATCHED;
                        rule_details = p->name;
                        break;
                    }
                }
            }

            if (CHECK_FLAG(srv_conf->waf_mode, MODE_EXTRA_CACHE) == TRUE) {
                lru_cache_manager_add(&srv_conf->white_referer_inspection_cache, 
                                        p_referer->data, 
                                        p_referer->len, 
                                        ret_value, 
                                        rule_details);
            }

            if (ret_value == MATCHED) {
                ctx->blocked = TRUE;
                strcpy((char*)ctx->rule_type, "WHITE-REFERER");
                strcpy((char*)ctx->rule_deatils, (char*)rule_details);
                *out_http_status = NGX_DECLINED;
            }
        }

        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Inspection is over.");
    }

    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: The Referer whitelist inspection process is fully completed.");
    return ret_value;
}


static ngx_int_t ngx_http_waf_handler_check_black_referer(ngx_http_request_t* r, ngx_int_t* out_http_status) {
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: Start inspecting the Referer blacklist.");

    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: The module context has been obtained.");

    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: The configuration of the module has been obtained.");

    ngx_int_t ret_value = NOT_MATCHED;

    if (CHECK_FLAG(srv_conf->waf_mode, MODE_INSPECT_REFERER) == FALSE) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Because this Inspection is disabled in the configuration, no Inspection is performed.");
        ret_value = NOT_MATCHED;
    } else if (CHECK_FLAG(srv_conf->waf_mode, r->method) == FALSE) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Because this Http.Method is disabled in the configuration, no Inspection is performed.");
        ret_value = NOT_MATCHED;
    } else if (r->headers_in.referer == NULL) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: The Inspection is skipped because the Referer is empty.");
        ret_value = NOT_MATCHED;
    } else {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Inspection has begun.");

        ngx_str_t* p_referer = &r->headers_in.referer->value;
        ngx_regex_elt_t* p = srv_conf->black_referer->elts;


        if (p_referer->data == NULL || p_referer->len == 0) {
            ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: The Inspection is skipped because the Referer is empty.");
            ret_value = NOT_MATCHED;
        } else {
            u_char* rule_details = NULL;
            ngx_int_t cache_hit = FAIL;
            if (CHECK_FLAG(srv_conf->waf_mode, MODE_EXTRA_CACHE) == TRUE) {
                cache_hit = lru_cache_manager_find(&srv_conf->black_referer_inspection_cache, 
                                                    p_referer->data, 
                                                    p_referer->len, 
                                                    &ret_value, 
                                                    &rule_details);
            }

            if (cache_hit != SUCCESS) {
                for (size_t i = 0; i < srv_conf->black_referer->nelts; i++, p++) {
                    ngx_int_t rc = ngx_regex_exec(p->regex, p_referer, NULL, 0);
                    if (rc >= 0) {
                        ret_value = MATCHED;
                        rule_details = p->name;
                        break;
                    }
                }
            }

            if (CHECK_FLAG(srv_conf->waf_mode, MODE_EXTRA_CACHE) == TRUE) {
                lru_cache_manager_add(&srv_conf->black_referer_inspection_cache, 
                                        p_referer->data, 
                                        p_referer->len, 
                                        ret_value, 
                                        rule_details);
            }

            if (ret_value == MATCHED) {
                ctx->blocked = TRUE;
                strcpy((char*)ctx->rule_type, "BLACK-REFERER");
                strcpy((char*)ctx->rule_deatils, (char*)rule_details);
                *out_http_status = NGX_HTTP_FORBIDDEN;
            }
        }

        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Inspection is over.");
    }

    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: The Referer blacklist inspection process is fully completed.");
    return ret_value;
}


static ngx_int_t ngx_http_waf_handler_check_black_cookie(ngx_http_request_t* r, ngx_int_t* out_http_status) {
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: Start inspecting the Cookie blacklist.");

    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: The module context has been obtained.");

    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: The configuration of the module has been obtained.");

    ngx_int_t ret_value = NOT_MATCHED;

    if (CHECK_FLAG(srv_conf->waf_mode, MODE_INSPECT_COOKIE) == FALSE) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Because this Inspection is disabled in the configuration, no Inspection is performed.");
        ret_value = NOT_MATCHED;
    } else if (CHECK_FLAG(srv_conf->waf_mode, r->method) == FALSE) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Because this Http.Method is disabled in the configuration, no Inspection is performed.");
        ret_value = NOT_MATCHED;
    } else if (r->headers_in.cookies.nelts != 0) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Inspection has begun.");

        ngx_table_elt_t** ppcookie = r->headers_in.cookies.elts;
        size_t i;
        for (i = 0; i < r->headers_in.cookies.nelts; i++, ppcookie++) {
            ngx_regex_elt_t* p = srv_conf->black_cookie->elts;
            size_t j;
            for (j = 0; j < srv_conf->black_cookie->nelts; j++, p++) {
                if ((**ppcookie).key.data == NULL || (**ppcookie).key.len == 0) {
                    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
                        "ngx_waf_debug: The Inspection is skipped because the Cookie.key is empty.");
                    continue;
                }

                if ((**ppcookie).value.data == NULL || (**ppcookie).value.len == 0) {
                    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
                        "ngx_waf_debug: The Inspection is skipped because the Cookie.value is empty.");
                    continue;
                }

                ngx_str_t temp;
                temp.len = (**ppcookie).key.len + (**ppcookie).value.len;
                temp.data = (u_char*)ngx_pcalloc(r->pool, sizeof(u_char*) * temp.len);
                ngx_memcpy(temp.data, (**ppcookie).key.data, (**ppcookie).key.len);
                ngx_memcpy(temp.data + (**ppcookie).key.len, (**ppcookie).value.data, (**ppcookie).value.len);

                ngx_int_t cache_hit = FAIL;
                u_char* rule_detail = NULL;
                if (CHECK_FLAG(srv_conf->waf_mode, MODE_EXTRA_CACHE) == TRUE) {
                    cache_hit = lru_cache_manager_find(&srv_conf->black_cookie_inspection_cache,
                                                       temp.data,
                                                       temp.len,
                                                       &ret_value,
                                                       &rule_detail);
                }
 
                if (cache_hit != SUCCESS && ngx_regex_exec(p->regex, &temp, NULL, 0) >= 0) {
                    rule_detail = p->name;
                    ret_value = MATCHED;
                }

                if (CHECK_FLAG(srv_conf->waf_mode, MODE_EXTRA_CACHE) == TRUE) {
                    lru_cache_manager_add(&srv_conf->black_cookie_inspection_cache,
                                          temp.data,
                                          temp.len,
                                          ret_value,
                                          rule_detail);
                }

                ngx_pfree(r->pool, temp.data);

                if (ret_value == MATCHED) {
                    ctx->blocked = TRUE;
                    strcpy((char*)ctx->rule_type, "BLACK-COOKIE");
                    strcpy((char*)ctx->rule_deatils, (char*)rule_detail);
                    *out_http_status = NGX_HTTP_FORBIDDEN;
                    ret_value = MATCHED;
                    break;
                }
            }
            if (ret_value == MATCHED) {
                break;
            }
        }

        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Inspection is over.");
    }

    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: The Cookie blacklist inspection process is fully completed.");
    return ret_value;
}


static void check_post(ngx_http_request_t* r) {
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: Start inspecting the Post-Body blacklist.");

    ngx_http_waf_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: The module context has been obtained.");

    ngx_http_waf_srv_conf_t* srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: The configuration of the module has been obtained.");
    
    ngx_chain_t* buf_chain = r->request_body == NULL ? NULL : r->request_body->bufs;
    ngx_buf_t* body_buf = NULL;
    ngx_str_t body_str;

    ctx->read_body_done = TRUE;

    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Inspection has begun.");

    while (buf_chain != NULL) {
        body_buf = buf_chain->buf;

        if (body_buf == NULL) {
            break;
        }

        body_str.data = body_buf->pos;
        body_str.len = body_buf->last - body_buf->pos;


        if (!ngx_buf_in_memory(body_buf)) {
            ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
                "ngx_waf_debug: The detection is skipped because the Post-Body is not in memory.");
            buf_chain = buf_chain->next;
            continue;
        }

        ngx_regex_elt_t* p = srv_conf->black_post->elts;
        ngx_int_t rc;
        size_t i;
        for (i = 0; i < srv_conf->black_post->nelts; i++, p++) {
            rc = ngx_regex_exec(p->regex, &body_str, NULL, 0);
            if (rc >= 0) {
                ctx->blocked = TRUE;
                strcpy((char*)ctx->rule_type, "BLACK-POST");
                strcpy((char*)ctx->rule_deatils, (char*)p->name);
                ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "ngx_waf: [%s][%s]", ctx->rule_type, ctx->rule_deatils);
                ngx_http_finalize_request(r, NGX_HTTP_FORBIDDEN);
                break;
            }
        }

        if (ctx->blocked != TRUE) {
            break;
        }

        buf_chain = buf_chain->next;
    }

    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Inspection is over.");

    if (ctx->blocked != TRUE) {
        ngx_http_finalize_request(r, NGX_DONE);
        ngx_http_core_run_phases(r);
    }
}


#endif
