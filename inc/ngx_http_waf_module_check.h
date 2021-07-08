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
#include <ngx_http_waf_module_spinlock.h>
#include <libinjection/src/libinjection.h>
#include <libinjection/src/libinjection_sqli.h>
#include <libinjection/src/libinjection_xss.h>


#ifndef NGX_HTTP_WAF_MODLULE_CHECK_H
#define NGX_HTTP_WAF_MODLULE_CHECK_H

extern ngx_module_t ngx_http_waf_module; /**< 模块详情 */

extern char ngx_http_waf_module_nonce[17];

static void ngx_http_waf_handler_cleanup(void *data);

/**
 * @defgroup check 规则匹配模块
 * @brief 检查诸如 IP，URL 等是否命中规则。
 * @addtogroup check 规则匹配模块
 * @{
*/


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
static void ngx_http_waf_handler_check_black_post(ngx_http_request_t* r);


/**
 * @brief 获取模块上下文和 server 块配置。
*/
static void ngx_http_waf_get_ctx_and_conf(ngx_http_request_t* r, ngx_http_waf_srv_conf_t** srv_conf, ngx_http_waf_ctx_t** ctx);


/**
 * @brief 测试数组内的所有正则
 * @param[in] str 被测试的字符串
 * @param[in] array 包含若干个正则的数组
 * @param[in] rule_type 触发规则时的规则类型
 * @param[in] cache 检测时所使用的缓存管理器
 * @return 如果匹配到返回 NGX_HTTP_WAF_MATCHED，反之则为 NGX_HTTP_WAF_NOT_MATCHED。
*/
static ngx_int_t ngx_http_waf_regex_exec_arrray_sqli_xss(ngx_http_request_t* r, 
                                                        ngx_str_t* str, 
                                                        ngx_array_t* array, 
                                                        const u_char* rule_type, 
                                                        spinlock_t* lock,
                                                        redis_key_type_e key_type,
                                                        int check_sql_injection,
                                                        int check_xss);

/**
 * @}
*/


static ngx_int_t ngx_http_waf_handler_check_white_ip(ngx_http_request_t* r, ngx_int_t* out_http_status) {
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: Start inspecting the IP whitelist.");

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_srv_conf_t* srv_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &srv_conf, &ctx);

    ngx_int_t ret_value = NGX_HTTP_WAF_NOT_MATCHED;

    if (ngx_http_waf_check_flag(srv_conf->waf_mode, NGX_HTTP_WAF_MODE_INSPECT_IP) == NGX_HTTP_WAF_FALSE) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Because this Inspection is disabled in the configuration, no Inspection is performed.");
        ret_value = NGX_HTTP_WAF_NOT_MATCHED;
    } else {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Inspection has begun.");

        ip_trie_node_t* ip_trie_node = NULL;
        if (r->connection->sockaddr->sa_family == AF_INET) {
            struct sockaddr_in* sin = (struct sockaddr_in*)r->connection->sockaddr;
            inx_addr_t inx_addr;
            ngx_memcpy(&(inx_addr.ipv4), &(sin->sin_addr), sizeof(struct in_addr));
            if (ip_trie_find(&srv_conf->white_ipv4, &inx_addr, &ip_trie_node) == NGX_HTTP_WAF_SUCCESS) {
                ctx->blocked = NGX_HTTP_WAF_FALSE;
                strcpy((char*)ctx->rule_type, "WHITE-IPV4");
                strcpy((char*)ctx->rule_deatils, (char*)ip_trie_node->data);
                *out_http_status = NGX_DECLINED;
                ret_value = NGX_HTTP_WAF_MATCHED;
            }
        } else if (r->connection->sockaddr->sa_family == AF_INET6) {
            struct sockaddr_in6* sin6 = (struct sockaddr_in6*)r->connection->sockaddr;
            inx_addr_t inx_addr;
            
            ngx_memcpy(&(inx_addr.ipv6), &(sin6->sin6_addr), sizeof(struct in6_addr));
            if (ip_trie_find(&srv_conf->white_ipv6, &inx_addr, &ip_trie_node) == NGX_HTTP_WAF_SUCCESS) {
                ctx->blocked = NGX_HTTP_WAF_FALSE;
                strcpy((char*)ctx->rule_type, "WHITE-IPV6");
                strcpy((char*)ctx->rule_deatils, (char*)ip_trie_node->data);
                *out_http_status = NGX_DECLINED;
                ret_value = NGX_HTTP_WAF_MATCHED;
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

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_srv_conf_t* srv_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &srv_conf, &ctx);
    
    ngx_int_t ret_value = NGX_HTTP_WAF_NOT_MATCHED;

    if (ngx_http_waf_check_flag(srv_conf->waf_mode, NGX_HTTP_WAF_MODE_INSPECT_IP) == NGX_HTTP_WAF_FALSE) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Because this Inspection is disabled in the configuration, no Inspection is performed.");
        ret_value = NGX_HTTP_WAF_NOT_MATCHED;
    } else {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Inspection has begun.");

        ip_trie_node_t *ip_trie_node = NULL;
        if (r->connection->sockaddr->sa_family == AF_INET) {
            struct sockaddr_in* sin = (struct sockaddr_in*)r->connection->sockaddr;
            inx_addr_t inx_addr;
            
            ngx_memcpy(&(inx_addr.ipv4), &(sin->sin_addr), sizeof(struct in_addr));
            if (ip_trie_find(&srv_conf->black_ipv4, &inx_addr, &ip_trie_node) == NGX_HTTP_WAF_SUCCESS) {
                ctx->blocked = NGX_HTTP_WAF_TRUE;
                strcpy((char*)ctx->rule_type, "BLACK-IPV4");
                strcpy((char*)ctx->rule_deatils, (char*)ip_trie_node->data);
                *out_http_status = NGX_HTTP_FORBIDDEN;
                ret_value = NGX_HTTP_WAF_MATCHED;
            }
        } else if (r->connection->sockaddr->sa_family == AF_INET6) {
            struct sockaddr_in6* sin6 = (struct sockaddr_in6*)r->connection->sockaddr;
            inx_addr_t inx_addr;
            ngx_memcpy(&(inx_addr.ipv6), &(sin6->sin6_addr), sizeof(struct in6_addr));
            if (ip_trie_find(&srv_conf->black_ipv6, &inx_addr, &ip_trie_node) == NGX_HTTP_WAF_SUCCESS) {
                ctx->blocked = NGX_HTTP_WAF_TRUE;
                strcpy((char*)ctx->rule_type, "BLACK-IPV6");
                strcpy((char*)ctx->rule_deatils, (char*)ip_trie_node->data);
                *out_http_status = srv_conf->waf_http_status;
                ret_value = NGX_HTTP_WAF_MATCHED;
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

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_srv_conf_t* srv_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &srv_conf, &ctx);
    
    ngx_int_t ret_value = NGX_HTTP_WAF_NOT_MATCHED;
    
    if (ngx_http_waf_check_flag(srv_conf->waf_mode, NGX_HTTP_WAF_MODE_INSPECT_CC) == NGX_HTTP_WAF_FALSE) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Because this detection is disabled in the configuration, no detection is performed.");
        ret_value = NGX_HTTP_WAF_NOT_MATCHED;
    } else if (srv_conf->waf_cc_deny_limit == NGX_CONF_UNSET
        || srv_conf->waf_cc_deny_duration == NGX_CONF_UNSET) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Because this detection is disabled in the configuration, no detection is performed.");
        ret_value = NGX_HTTP_WAF_NOT_MATCHED;
    } else {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Detection has begun.");

        inx_addr_t inx_addr;
        ngx_memzero(&inx_addr, sizeof(inx_addr_t));

        if (r->connection->sockaddr->sa_family == AF_INET) {
            struct sockaddr_in* s_addr_in = (struct sockaddr_in*)(r->connection->sockaddr);
            ngx_memcpy(&(inx_addr.ipv4), &(s_addr_in->sin_addr), sizeof(struct in_addr));
        } else {
            struct sockaddr_in6* s_addr_in6 = (struct sockaddr_in6*)(r->connection->sockaddr);
            ngx_memcpy(&(inx_addr.ipv6), &(s_addr_in6->sin6_addr), sizeof(struct in6_addr));
        }

        if (ngx_http_waf_spinlock_lock(&(srv_conf->cc_lock)) == NGX_HTTP_WAF_SUCCESS) {
            char buf[2 * sizeof(inx_addr_t) + sizeof(char)];
            sodium_bin2hex(buf, sizeof(buf), (unsigned char*)(&inx_addr), sizeof(inx_addr_t));

            /* 查询该 IP 是否已经被 CC 防护拦截 */
            redisReply* reply = redisCommand(srv_conf->redis_ctx,
                                             "GET %s_%s_keytype%d_%s_cc_deny",
                                             ngx_http_waf_module_nonce,
                                             (char*)(srv_conf->redis_key_prefix),
                                             REDIS_KEY_TYPE_IP,
                                             buf);

            /* 如果没有出错 */
            if (reply != NULL) {
                /* 如果该 IP 已经被 CC 防护拦截 */
                if (reply->type == REDIS_REPLY_STRING
                 && strcmp(reply->str, "true") == 0) {
                    ret_value = NGX_HTTP_WAF_MATCHED;
                    ctx->blocked = NGX_HTTP_WAF_TRUE;
                    *out_http_status = srv_conf->waf_http_status_cc;
                    freeReplyObject(reply);
                } else {
                    freeReplyObject(reply);
                    reply = NULL;

                    /* 尝试创建该 IP 的访问统计信息 */
                    reply = redisCommand(srv_conf->redis_ctx,
                                         "SET %s_%s_keytype%d_%s 1 NX EX %d",
                                         ngx_http_waf_module_nonce,
                                         (char*)(srv_conf->redis_key_prefix),
                                         REDIS_KEY_TYPE_IP,
                                         buf,
                                         srv_conf->waf_cc_deny_cycle);

                    /* 如果没有出错 */
                    if (reply != NULL) {
                        /* 如果创建成功 */
                        if (reply->type == REDIS_REPLY_STATUS && strcasecmp(reply->str, "OK")) {
                            ctx->blocked = NGX_HTTP_WAF_FALSE;
                            *out_http_status = NGX_DECLINED;
                            freeReplyObject(reply);
                        /* 如果已经存在 */
                        } else if (reply->type == REDIS_REPLY_NIL) {
                            freeReplyObject(reply);
                            reply = NULL;

                            /* 增加访问次数 */
                            reply = redisCommand(srv_conf->redis_ctx,
                                                 "INCR %s_%s_keytype%d_%s",
                                                 ngx_http_waf_module_nonce,
                                                 (char*)(srv_conf->redis_key_prefix),
                                                 REDIS_KEY_TYPE_IP,
                                                 buf);

                            /* 如果没有出错且超出访问频率限制 */
                            if (reply != NULL 
                             && reply->type == REDIS_REPLY_INTEGER 
                             && reply->integer > srv_conf->waf_cc_deny_limit) {
                                freeReplyObject(reply);
                                reply = NULL;

                                /* 将 IP 标记为被 CC 防护拦截 */
                                reply = redisCommand(srv_conf->redis_ctx,
                                                    "SET %s_%s_keytype%d_%s_cc_deny true EX %d",
                                                    ngx_http_waf_module_nonce,
                                                    (char*)(srv_conf->redis_key_prefix),
                                                    REDIS_KEY_TYPE_IP,
                                                    buf,
                                                    srv_conf->waf_cc_deny_duration);
                                ret_value = NGX_HTTP_WAF_MATCHED;
                                ctx->blocked = NGX_HTTP_WAF_TRUE;
                                *out_http_status = srv_conf->waf_http_status_cc;
                                freeReplyObject(reply);
                            } else {
                                ctx->blocked = NGX_HTTP_WAF_FALSE;
                                *out_http_status = NGX_DECLINED;
                            }
                        } else {
                            ctx->blocked = NGX_HTTP_WAF_FALSE;
                            *out_http_status = NGX_DECLINED;
                            freeReplyObject(reply);
                        }
                    } else {
                        ctx->blocked = NGX_HTTP_WAF_FALSE;
                        *out_http_status = NGX_DECLINED;
                    }
                }
            } else {
                ctx->blocked = NGX_HTTP_WAF_FALSE;
                *out_http_status = NGX_DECLINED;
            }

            if (ngx_http_waf_spinlock_unlock(&(srv_conf->cc_lock)) != NGX_HTTP_WAF_SUCCESS) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, 
                    "ngx_waf_debug: Unable to unlock %s.", srv_conf->cc_lock.id);
                }

        } else {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, 
                "ngx_waf_debug: Unable to lock %s.", srv_conf->cc_lock.id);
        }
        

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

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_srv_conf_t* srv_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &srv_conf, &ctx);

    ngx_int_t ret_value = NGX_HTTP_WAF_NOT_MATCHED;

    if (ngx_http_waf_check_flag(srv_conf->waf_mode, NGX_HTTP_WAF_MODE_INSPECT_URL | r->method) == NGX_HTTP_WAF_FALSE) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Because this detection is disabled in the configuration, no detection is performed.");
        ret_value = NGX_HTTP_WAF_NOT_MATCHED;
    } else {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Inspection has begun.");

        ngx_str_t* p_uri = &r->uri;
        ngx_array_t* regex_array = srv_conf->white_url;

        ret_value = ngx_http_waf_regex_exec_arrray_sqli_xss(r,
                                                            p_uri, 
                                                            regex_array, 
                                                            (u_char*)"WHITE-URL", 
                                                            &(srv_conf->white_url_cache_lock),
                                                            REDIS_KEY_TYPE_WHITE_URL,
                                                            NGX_HTTP_WAF_FALSE, 
                                                            NGX_HTTP_WAF_FALSE);

        if (ret_value == NGX_HTTP_WAF_MATCHED) {
            ctx->blocked = NGX_HTTP_WAF_FALSE;
            *out_http_status = NGX_DECLINED;
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

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_srv_conf_t* srv_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &srv_conf, &ctx);

    ngx_int_t ret_value = NGX_HTTP_WAF_NOT_MATCHED;

    if (ngx_http_waf_check_flag(srv_conf->waf_mode, NGX_HTTP_WAF_MODE_INSPECT_URL | r->method) == NGX_HTTP_WAF_FALSE) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Because this Inspection is disabled in the configuration, no Inspection is performed.");
        ret_value = NGX_HTTP_WAF_NOT_MATCHED;
    } else {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Inspection has begun.");

        ngx_str_t* p_uri = &r->uri;
        ngx_array_t* regex_array = srv_conf->black_url;

        ret_value = ngx_http_waf_regex_exec_arrray_sqli_xss(r, 
                                                            p_uri, 
                                                            regex_array, 
                                                            (u_char*)"BLACK-URL", 
                                                            &(srv_conf->black_url_cache_lock),
                                                            REDIS_KEY_TYPE_URL,
                                                            NGX_HTTP_WAF_TRUE,
                                                            NGX_HTTP_WAF_FALSE);

        if (ret_value == NGX_HTTP_WAF_MATCHED) {
            ctx->blocked = NGX_HTTP_WAF_TRUE;
            *out_http_status = srv_conf->waf_http_status;
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

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_srv_conf_t* srv_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &srv_conf, &ctx);

    ngx_int_t ret_value = NGX_HTTP_WAF_NOT_MATCHED;

    if (ngx_http_waf_check_flag(srv_conf->waf_mode, NGX_HTTP_WAF_MODE_INSPECT_ARGS | r->method) == NGX_HTTP_WAF_FALSE) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Because this Inspection is disabled in the configuration, no Inspection is performed.");
        ret_value = NGX_HTTP_WAF_NOT_MATCHED;
    } else {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Inspection has begun.");

        ngx_str_t* p_args = &r->args;
        ngx_array_t* regex_array = srv_conf->black_args;

        ret_value = ngx_http_waf_regex_exec_arrray_sqli_xss(r, 
                                                            p_args, 
                                                            regex_array, 
                                                            (u_char*)"BLACK-ARGS", 
                                                            &(srv_conf->black_args_cache_lock),
                                                            REDIS_KEY_TYPE_QUERY_STRING,
                                                            NGX_HTTP_WAF_TRUE,
                                                            NGX_HTTP_WAF_FALSE);

        if (ret_value != NGX_HTTP_WAF_MATCHED) {
            UT_array* args = NULL;
            ngx_str_split(p_args, '&', p_args->len, &args);
            ngx_str_t* p = NULL;
            while (p = (ngx_str_t*)utarray_next(args, p), p != NULL) {
                UT_array* key_value = NULL;
                if (ngx_str_split(p, '=', p_args->len, &key_value) == NGX_HTTP_WAF_TRUE
                    && utarray_len(key_value) == 2) {
                    ngx_str_t* key = NULL;
                    ngx_str_t* value = NULL;
                    key = (ngx_str_t*)utarray_next(key_value, NULL);
                    value = (ngx_str_t*)utarray_next(key_value, key);
                    ret_value = ngx_http_waf_regex_exec_arrray_sqli_xss(r, 
                                                                        key, 
                                                                        regex_array, 
                                                                        (u_char*)"BLACK-ARGS", 
                                                                        &(srv_conf->black_args_cache_lock),
                                                                        REDIS_KEY_TYPE_QUERY_STRING,
                                                                        NGX_HTTP_WAF_TRUE,
                                                                        NGX_HTTP_WAF_TRUE);
                    if (ret_value == NGX_HTTP_WAF_MATCHED) {
                        break;
                    }

                    ret_value = ngx_http_waf_regex_exec_arrray_sqli_xss(r, 
                                                                        value, 
                                                                        regex_array, 
                                                                        (u_char*)"BLACK-ARGS", 
                                                                        &(srv_conf->black_args_cache_lock),
                                                                        REDIS_KEY_TYPE_QUERY_STRING,
                                                                        NGX_HTTP_WAF_TRUE,
                                                                        NGX_HTTP_WAF_TRUE);

                    if (ret_value == NGX_HTTP_WAF_MATCHED) {
                        break;
                    }
                }
                utarray_free(key_value);
            }
            utarray_free(args);
        }

        if (ret_value == NGX_HTTP_WAF_MATCHED) {
            ctx->blocked = NGX_HTTP_WAF_TRUE;
            *out_http_status = srv_conf->waf_http_status;
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

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_srv_conf_t* srv_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &srv_conf, &ctx);

    ngx_int_t ret_value = NGX_HTTP_WAF_NOT_MATCHED;

    if (ngx_http_waf_check_flag(srv_conf->waf_mode, NGX_HTTP_WAF_MODE_INSPECT_UA | r->method) == NGX_HTTP_WAF_FALSE) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Because this Inspection is disabled in the configuration, no Inspection is performed.");
        ret_value = NGX_HTTP_WAF_NOT_MATCHED;
    } else if (r->headers_in.user_agent == NULL) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: The Inspection is skipped because the User-Agent is empty.");
        ret_value = NGX_HTTP_WAF_NOT_MATCHED;
    } else {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Inspection has begun.");

        ngx_str_t* p_ua = &r->headers_in.user_agent->value;
        ngx_array_t* regex_array = srv_conf->black_ua;

        ret_value = ngx_http_waf_regex_exec_arrray_sqli_xss(r, 
                                                            p_ua, 
                                                            regex_array, 
                                                            (u_char*)"BLACK-UA", 
                                                            &(srv_conf->black_ua_cache_lock),
                                                            REDIS_KEY_TYPE_USER_AGENT,
                                                            NGX_HTTP_WAF_FALSE,
                                                            NGX_HTTP_WAF_FALSE);

        if (ret_value == NGX_HTTP_WAF_MATCHED) {
            ctx->blocked = NGX_HTTP_WAF_TRUE;
            *out_http_status = srv_conf->waf_http_status;
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

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_srv_conf_t* srv_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &srv_conf, &ctx);

    ngx_int_t ret_value = NGX_HTTP_WAF_NOT_MATCHED;

    if (ngx_http_waf_check_flag(srv_conf->waf_mode, NGX_HTTP_WAF_MODE_INSPECT_REFERER | r->method) == NGX_HTTP_WAF_FALSE) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Because this Inspection is disabled in the configuration, no Inspection is performed.");
        ret_value = NGX_HTTP_WAF_NOT_MATCHED;
    } else if (r->headers_in.referer == NULL) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: The Inspection is skipped because the Referer is empty.");
        ret_value = NGX_HTTP_WAF_NOT_MATCHED;
    } else {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Inspection has begun.");

        ngx_str_t* p_referer = &r->headers_in.referer->value;
        ngx_array_t* regex_array = srv_conf->white_referer;

        ret_value = ngx_http_waf_regex_exec_arrray_sqli_xss(r, 
                                                            p_referer, 
                                                            regex_array, 
                                                            (u_char*)"WHITE-REFERER", 
                                                            &(srv_conf->white_referer_cache_lock),
                                                            REDIS_KEY_TYPE_WHITE_REFERER,
                                                            NGX_HTTP_WAF_FALSE,
                                                            NGX_HTTP_WAF_FALSE);

        if (ret_value == NGX_HTTP_WAF_MATCHED) {
            ctx->blocked = NGX_HTTP_WAF_FALSE;
            *out_http_status = NGX_DECLINED;
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

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_srv_conf_t* srv_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &srv_conf, &ctx);

    ngx_int_t ret_value = NGX_HTTP_WAF_NOT_MATCHED;

    if (ngx_http_waf_check_flag(srv_conf->waf_mode, NGX_HTTP_WAF_MODE_INSPECT_REFERER | r->method) == NGX_HTTP_WAF_FALSE) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Because this Inspection is disabled in the configuration, no Inspection is performed.");
        ret_value = NGX_HTTP_WAF_NOT_MATCHED;
    } else if (r->headers_in.referer == NULL) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: The Inspection is skipped because the Referer is empty.");
        ret_value = NGX_HTTP_WAF_NOT_MATCHED;
    } else {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Inspection has begun.");

        ngx_str_t* p_referer = &r->headers_in.referer->value;
        ngx_array_t* regex_array = srv_conf->black_referer;

        ret_value = ngx_http_waf_regex_exec_arrray_sqli_xss(r, 
                                                            p_referer, 
                                                            regex_array, 
                                                            (u_char*)"BLACK-REFERER", 
                                                            &(srv_conf->black_referer_cache_lock),
                                                            REDIS_KEY_TYPE_REFERER,
                                                            NGX_HTTP_WAF_FALSE,
                                                            NGX_HTTP_WAF_FALSE);

        if (ret_value == NGX_HTTP_WAF_MATCHED) {
            ctx->blocked = NGX_HTTP_WAF_TRUE;
            *out_http_status = srv_conf->waf_http_status;
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

    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_srv_conf_t* srv_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &srv_conf, &ctx);

    ngx_int_t ret_value = NGX_HTTP_WAF_NOT_MATCHED;

    if (ngx_http_waf_check_flag(srv_conf->waf_mode, NGX_HTTP_WAF_MODE_INSPECT_COOKIE | r->method) == NGX_HTTP_WAF_FALSE) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Because this Inspection is disabled in the configuration, no Inspection is performed.");
        ret_value = NGX_HTTP_WAF_NOT_MATCHED;
    } else if (r->headers_in.cookies.nelts != 0) {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Inspection has begun.");

        ngx_table_elt_t** ppcookie = r->headers_in.cookies.elts;
        size_t i;
        for (i = 0; i < r->headers_in.cookies.nelts; i++, ppcookie++) {
            ngx_str_t* native_cookies = &((**ppcookie).value);
            UT_array* cookies = NULL;
            if (parse_cookie(native_cookies, &cookies) != NGX_HTTP_WAF_SUCCESS) {
                continue;
            }

            ngx_str_t* key = NULL;
            ngx_str_t* value = NULL;
            ngx_str_t* p = NULL;

            do {
                if (key = (ngx_str_t*)utarray_next(cookies, p), p = key, key == NULL) {
                    break;
                }

                if (value = (ngx_str_t*)utarray_next(cookies, p), p = value, value == NULL) {
                    break;
                }

                ngx_str_t temp;
                temp.len = key->len + value->len;
                temp.data = (u_char*)ngx_pcalloc(r->pool, sizeof(u_char*) * temp.len);
                ngx_memcpy(temp.data, key->data, key->len);
                ngx_memcpy(temp.data + key->len, value->data, sizeof(u_char) * value->len);

                ngx_array_t* regex_array = srv_conf->black_cookie;

                ret_value = ngx_http_waf_regex_exec_arrray_sqli_xss(r, 
                                                                    &temp, 
                                                                    regex_array, 
                                                                    (u_char*)"BLACK-COOKIE", 
                                                                    &(srv_conf->black_cookie_cache_lock),
                                                                    REDIS_KEY_TYPE_COOKIE,
                                                                    NGX_HTTP_WAF_TRUE,
                                                                    NGX_HTTP_WAF_TRUE);

                if (ret_value != NGX_HTTP_WAF_MATCHED) {
                    ret_value = ngx_http_waf_regex_exec_arrray_sqli_xss(r, 
                                                                        key, 
                                                                        regex_array, 
                                                                        (u_char*)"BLACK-COOKIE", 
                                                                        &(srv_conf->black_cookie_cache_lock),
                                                                        REDIS_KEY_TYPE_COOKIE,
                                                                        NGX_HTTP_WAF_TRUE,
                                                                        NGX_HTTP_WAF_TRUE);
                }

                if (ret_value != NGX_HTTP_WAF_MATCHED) {
                    ret_value = ngx_http_waf_regex_exec_arrray_sqli_xss(r, 
                                                                        value, 
                                                                        regex_array, 
                                                                        (u_char*)"BLACK-COOKIE", 
                                                                        &(srv_conf->black_cookie_cache_lock),
                                                                        REDIS_KEY_TYPE_COOKIE,
                                                                        NGX_HTTP_WAF_TRUE,
                                                                        NGX_HTTP_WAF_TRUE);
                }

                ngx_pfree(r->pool, temp.data);
                
                if (ret_value == NGX_HTTP_WAF_MATCHED) {
                    ctx->blocked = NGX_HTTP_WAF_TRUE;
                    *out_http_status = srv_conf->waf_http_status;
                    break;
                }

            } while (p != NULL);

            utarray_free(cookies);

            if (ctx->blocked == NGX_HTTP_WAF_TRUE) {
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


static void ngx_http_waf_handler_check_black_post(ngx_http_request_t* r) {
    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: Start inspecting the Post-Body blacklist.");

    double start_clock = (double)clock();
    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_srv_conf_t* srv_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &srv_conf, &ctx);

    ngx_int_t content_length = ngx_atoi(r->headers_in.content_length->value.data, r->headers_in.content_length->value.len);
    ngx_chain_t* buf_chain = r->request_body == NULL ? NULL : r->request_body->bufs;
    ngx_str_t body_str;
    body_str.data = ngx_palloc(r->pool, content_length);
    body_str.len = 0;

    ctx->read_body_done = NGX_HTTP_WAF_TRUE;

    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Inspection has begun.");


    ngx_int_t cur_buf_pos = 0;
    for (ngx_chain_t* i = buf_chain; i != NULL; i = i->next) {
        if (!ngx_buf_in_memory_only(i->buf)) {
            ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
                "ngx_waf_debug: The buffer is skipped because the Post-Body is not in memory.");
        } else {
            ngx_int_t buf_len = sizeof(u_char) * (i->buf->last - i->buf->pos);
            body_str.len += buf_len;
            ngx_memcpy(body_str.data + cur_buf_pos, i->buf->pos, buf_len);
            cur_buf_pos += buf_len;
        }
    }

    if (ngx_http_waf_regex_exec_arrray_sqli_xss(r, 
                                            &body_str, 
                                            srv_conf->black_post, 
                                            (u_char*)"BLACK-POST", 
                                            NULL,
                                            REDIS_KEY_TYPE_VOID,
                                            NGX_HTTP_WAF_TRUE,
                                            NGX_HTTP_WAF_TRUE) == NGX_HTTP_WAF_MATCHED) {
        ctx->blocked = NGX_HTTP_WAF_TRUE;
    }

    ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: Inspection is over.");

    double end_clock = (double)clock();
    ctx->spend += (end_clock - start_clock) / CLOCKS_PER_SEC * 1000;

    if (ctx->blocked != NGX_HTTP_WAF_TRUE) {
        ngx_http_finalize_request(r, NGX_DONE);
        ngx_http_core_run_phases(r);
    } else {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "ngx_waf: [%s][%s]", ctx->rule_type, ctx->rule_deatils);
        ngx_http_finalize_request(r, NGX_DONE);
        ngx_http_finalize_request(r, srv_conf->waf_http_status);
    }
}


static void ngx_http_waf_get_ctx_and_conf(ngx_http_request_t* r, ngx_http_waf_srv_conf_t** srv_conf, ngx_http_waf_ctx_t** ctx) {
    if (ctx != NULL) {
        *ctx = NULL;
        *ctx = ngx_http_get_module_ctx(r, ngx_http_waf_module);
        if (*ctx == NULL) {
            ngx_http_cleanup_t* cln = NULL;
            for (cln = r->cleanup; cln != NULL; cln = cln->next) {
                if (cln->handler == ngx_http_waf_handler_cleanup) {
                    *ctx = cln->data;
                }
            }
        }
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
            "ngx_waf_debug: The module context has been obtained.");
    }
    
    if (srv_conf != NULL) {
        *srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_waf_module);
        ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, 
        "ngx_waf_debug: The configuration of the module has been obtained.");
    }
}


static ngx_int_t ngx_http_waf_regex_exec_arrray_sqli_xss(ngx_http_request_t* r, 
                                                        ngx_str_t* str, 
                                                        ngx_array_t* array, 
                                                        const u_char* rule_type, 
                                                        spinlock_t* lock,
                                                        redis_key_type_e key_type,
                                                        int check_sql_injection,
                                                        int check_xss) {
    static char s_no_memory[] = "No Memory";

    ngx_http_waf_srv_conf_t* srv_conf = NULL;
    ngx_http_waf_ctx_t* ctx = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &srv_conf, &ctx);
    ngx_int_t cache_hit = NGX_HTTP_WAF_FAIL;
    ngx_int_t is_matched = NGX_HTTP_WAF_NOT_MATCHED;
    u_char* rule_detail = NULL;
    u_char* raw_str = ngx_pcalloc(r->pool, sizeof(u_char) * (str->len + 1));
    ngx_memcpy(raw_str, str->data, sizeof(u_char) * str->len);
    raw_str[str->len] = '\0';

    if (str == NULL || str->data == NULL || str->len == 0 || array->nelts == 0) {
        return NGX_HTTP_WAF_NOT_MATCHED;
    }

    if (lock != NULL && ngx_http_waf_spinlock_lock(lock) == NGX_HTTP_WAF_SUCCESS) {
        ngx_int_t flag = 0;
        if (ngx_http_waf_check_flag(srv_conf->waf_mode, NGX_HTTP_WAF_MODE_EXTRA_CACHE) == NGX_HTTP_WAF_TRUE) {
            redisReply* reply = redisCommand(srv_conf->redis_ctx,
                                            "HGET %s_%s_keytype%d_%s is_matched",
                                            ngx_http_waf_module_nonce,
                                            (char*)(srv_conf->redis_key_prefix),
                                            key_type,
                                            (char*)raw_str);
            
            if (reply != NULL && reply->type == REDIS_REPLY_STRING) {
                if (strcmp(reply->str, "true") == 0) {
                    is_matched = NGX_HTTP_WAF_MATCHED;
                } else {
                    is_matched = NGX_HTTP_WAF_NOT_MATCHED;
                }
                ++flag;
            }

            if (reply != NULL) { 
                freeReplyObject(reply);
                reply = NULL;
            }

            reply = redisCommand(srv_conf->redis_ctx,
                                 "HGET %s_%s_keytype%d_%s rule_detail",
                                 ngx_http_waf_module_nonce,
                                 (char*)(srv_conf->redis_key_prefix),
                                 key_type,
                                 (char*)raw_str);


            if (reply != NULL
            && reply->type == REDIS_REPLY_STRING) {
                rule_detail = ngx_pcalloc(r->pool, sizeof(u_char) * (reply->len + 1));
                strcpy((char*)rule_detail, reply->str);
                ++flag;
            }

            if (reply != NULL) { 
                freeReplyObject(reply);
                reply = NULL;
            }

            if (flag == 2) {
                cache_hit = NGX_HTTP_WAF_SUCCESS;
            }
        }

        if (lock != NULL && ngx_http_waf_spinlock_unlock(lock) != NGX_HTTP_WAF_SUCCESS) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "ngx_waf_debug: Unable to unlock %s.", lock->id);
        }
    } else if (lock != NULL) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "ngx_waf_debug: Unable to lock %s.", lock->id);
    }

    

    

    if (cache_hit != NGX_HTTP_WAF_SUCCESS) {
        if (check_sql_injection == NGX_HTTP_WAF_TRUE
            && ngx_http_waf_check_flag(srv_conf->waf_mode, NGX_HTTP_WAF_MODE_LIB_INJECTION_SQLI) == NGX_HTTP_WAF_TRUE) {
            sfilter sf;
            libinjection_sqli_init(&sf, 
                                (char*)(str->data), 
                                str->len,  
                                FLAG_NONE | FLAG_QUOTE_NONE | FLAG_QUOTE_SINGLE | FLAG_QUOTE_DOUBLE | FLAG_SQL_ANSI | FLAG_SQL_MYSQL);
            if (libinjection_is_sqli(&sf) == 1) {
                is_matched = NGX_HTTP_WAF_MATCHED;
                rule_detail = ngx_pcalloc(r->pool, sizeof(u_char) * 64);
                if (rule_detail != NULL) {
                    sprintf((char*)rule_detail, "libinjection_sqli - %s", sf.fingerprint);
                } else {
                    rule_detail = (u_char*)s_no_memory;
                }
            }
        }

        if (check_xss
            && ngx_http_waf_check_flag(srv_conf->waf_mode, NGX_HTTP_WAF_MODE_LIB_INJECTION_XSS) == NGX_HTTP_WAF_TRUE) {
            if (libinjection_xss((char*)(str->data), str->len) == 1) {
                is_matched = NGX_HTTP_WAF_MATCHED;
                rule_detail = ngx_pcalloc(r->pool, sizeof(u_char) * 64);
                if (rule_detail != NULL) {
                    sprintf((char*)rule_detail, "libinjection_xss");
                } else {
                    rule_detail = (u_char*)s_no_memory;
                }
            }
        }

        if (rule_detail == NULL) {
            ngx_regex_elt_t* p = (ngx_regex_elt_t*)(array->elts);
            for (size_t i = 0; i < array->nelts; i++, p++) {
                ngx_int_t rc = ngx_regex_exec(p->regex, str, NULL, 0);
                if (rc >= 0) {
                    is_matched = NGX_HTTP_WAF_MATCHED;
                    rule_detail = p->name;
                    break;
                }
            }
        }
    }

    if (cache_hit != NGX_HTTP_WAF_SUCCESS && lock != NULL && ngx_http_waf_spinlock_lock(lock) == NGX_HTTP_WAF_SUCCESS) {
        if (ngx_http_waf_check_flag(srv_conf->waf_mode, NGX_HTTP_WAF_MODE_EXTRA_CACHE) == NGX_HTTP_WAF_TRUE) {
            redisReply* reply = redisCommand(srv_conf->redis_ctx,
                                            "HSET %s_%s_keytype%d_%s is_matched %s rule_detail %s",
                                            ngx_http_waf_module_nonce,
                                            (char*)(srv_conf->redis_key_prefix),
                                            key_type,
                                            (char*)raw_str,
                                            is_matched == NGX_HTTP_WAF_MATCHED ? "true" : "false",
                                            rule_detail == NULL ? "none" : (char*)rule_detail);
            
            if (reply != NULL) {
                freeReplyObject(reply);
            }
        }

        if (lock != NULL && ngx_http_waf_spinlock_unlock(lock) != NGX_HTTP_WAF_SUCCESS) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "ngx_waf_debug: Unable to unlock %s.", lock->id);
        }
    } else if (lock != NULL) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "ngx_waf_debug: Unable to lock %s.", lock->id);
    }

    if (is_matched == NGX_HTTP_WAF_MATCHED) {
        strcpy((char*)ctx->rule_type, (char*)rule_type);
        strcpy((char*)ctx->rule_deatils, (char*)rule_detail);
    }

    return is_matched;
}


#endif
