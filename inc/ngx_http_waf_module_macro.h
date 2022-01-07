/**
 * @file ngx_http_waf_module_macro.h
 * @brief 定义一些必要的宏
*/

#ifndef NGX_HTTP_WAF_MODULE_MACRO_H
#define NGX_HTTP_WAF_MODULE_MACRO_H

#define NGX_HTTP_WAF_VERSION "v10.1.1"

#define NGX_HTTP_WAF_ASYNC_MODSECURITY       (0)

/* 对应配置文件的文件名 */
#define NGX_HTTP_WAF_IPV4_FILE               ("ipv4")
#define NGX_HTTP_WAF_IPV6_FILE               ("ipv6")
#define NGX_HTTP_WAF_URL_FILE                ("url")
#define NGX_HTTP_WAF_ARGS_FILE               ("args")
#define NGX_HTTP_WAF_UA_FILE                 ("user-agent")
#define NGX_HTTP_WAF_REFERER_FILE            ("referer")
#define NGX_HTTP_WAF_COOKIE_FILE             ("cookie")
#define NGX_HTTP_WAF_POST_FILE               ("post")
#define NGX_HTTP_WAF_WHITE_IPV4_FILE         ("white-ipv4")
#define NGX_HTTP_WAF_WHITE_IPV6_FILE         ("white-ipv6")
#define NGX_HTTP_WAF_WHITE_URL_FILE          ("white-url")
#define NGX_HTTP_WAF_WHITE_REFERER_FILE      ("white-referer")


#define NGX_HTTP_WAF_FALSE                   (0)

#define NGX_HTTP_WAF_FAIL                    (0)

#define NGX_HTTP_WAF_NOT_MATCHED             (0)

#define NGX_HTTP_WAF_TRUE                    (1)

#define NGX_HTTP_WAF_SUCCESS                 (1)

#define NGX_HTTP_WAF_MATCHED                 (1)

#define NGX_HTTP_WAF_PROCESSING              (2)

#define NGX_HTTP_WAF_MALLOC_ERROR            (3)

#define NGX_HTTP_WAF_KEY_EXISTS              (4)

#define NGX_HTTP_WAF_KEY_NOT_EXISTS          (5)

#define NGX_HTTP_WAF_FAKE_BOT                (6)

#define NGX_HTTP_WAF_ALLOW                   (7)

#define NGX_HTTP_WAF_CAPTCHA_CHALLENGE       (8)

#define NGX_HTTP_WAF_CAPTCHA_BAD             (9)

#define NGX_HTTP_WAF_CAPTCHA_PASS            (10)

#define NGX_HTTP_WAF_FAULT                   (11)

#define NGX_HTTP_WAF_NEXT_FILTER             (12)

#define NGX_HTTP_WAF_ALREADY_EXISTS          (13)


#define NGX_HTTP_WAF_HCAPTCHA                (1)

#define NGX_HTTP_WAF_RECAPTCHA_V2_CHECKBOX   (2)

#define NGX_HTTP_WAF_RECAPTCHA_V2_INVISIBLE  (3)

#define NGX_HTTP_WAF_RECAPTCHA_V3            (4)


/**
 * @def NGX_HTTP_WAF_RULE_MAX_LEN
 * @brief 每条规则的占用的最大字节数。
*/
#define NGX_HTTP_WAF_RULE_MAX_LEN            (256 * 4 * 8)

/**
 * @def NGX_HTTP_WAF_INITIAL_SIZE
 * @brief 初始化配置块内存池时的初始内存池大小。
*/
#define NGX_HTTP_WAF_INITIAL_SIZE            (1024 * 1024 * 5)

#define NGX_HTTP_WAF_MAX_ALLOC_TIMES         (100000)

/**
 * @def NGX_HTTP_WAF_SHARE_MEMORY_NAME
 * @brief 用于 CC 防护的共享内存的名称
*/
#define NGX_HTTP_WAF_SHARE_MEMORY_CC_DNEY_NAME                   ("__ADD-SP_NGX_WAF_CC_DENY_SHM__")

/**
 * @def NGX_HTTP_WAF_ZONE_SIZE_MIN
 * @brief zone 的最小大小（字节）
*/
#define NGX_HTTP_WAF_ZONE_SIZE_MIN                              (1024 * 1024 * 5)


/**
 * @def NGX_HTTP_WAF_UID_LEN
 * @brief 用于 Under Attack 模式的 UID 字符串的长度
*/
#define NGX_HTTP_WAF_UID_LEN                                     (64)


/**
 * @def CACHE_ITEM_MIN_SIZE
 * @brief 用于设置缓存项数的上限
*/
#define NGX_HTTP_WAF_CACHE_ITEM_MIN_NUM                          (50)

/**
 * @def NGX_HTTP_WAF_MODE_INSPECT_GET
 * @brief 对 GET 请求进行检查
*/
#define NGX_HTTP_WAF_MODE_INSPECT_GET                        NGX_HTTP_GET

/**
 * @def NGX_HTTP_WAF_MODE_INSPECT_HEAD
 * @brief 对 HEAD 请求进行检查
*/
#define NGX_HTTP_WAF_MODE_INSPECT_HEAD                       NGX_HTTP_HEAD

/**
 * @def NGX_HTTP_WAF_MODE_INSPECT_POST
 * @brief 对 POST 请求进行检查
*/
#define NGX_HTTP_WAF_MODE_INSPECT_POST                       NGX_HTTP_POST

/**
 * @def NGX_HTTP_WAF_MODE_INSPECT_PUT
 * @brief 对 PUT 请求进行检查
*/
#define NGX_HTTP_WAF_MODE_INSPECT_PUT                        NGX_HTTP_PUT

/**
 * @def NGX_HTTP_WAF_MODE_INSPECT_DELETE
 * @brief 对 DELETE 请求进行检查
*/
#define NGX_HTTP_WAF_MODE_INSPECT_DELETE                     NGX_HTTP_DELETE

/**
 * @def NGX_HTTP_WAF_MODE_INSPECT_MKCOL
 * @brief 对 MKCOL 请求进行检查
*/
#define NGX_HTTP_WAF_MODE_INSPECT_MKCOL                      NGX_HTTP_MKCOL

/**
 * @def NGX_HTTP_WAF_MODE_INSPECT_COPY
 * @brief 对 COPY 请求进行检查
*/
#define NGX_HTTP_WAF_MODE_INSPECT_COPY                       NGX_HTTP_COPY

/**
 * @def NGX_HTTP_WAF_MODE_INSPECT_MOVE
 * @brief 对 MOVE 请求进行检查
*/
#define NGX_HTTP_WAF_MODE_INSPECT_MOVE                       NGX_HTTP_MOVE

/**
 * @def NGX_HTTP_WAF_MODE_INSPECT_OPTIONS
 * @brief 对 OPTIONS 请求进行检查
*/
#define NGX_HTTP_WAF_MODE_INSPECT_OPTIONS                    NGX_HTTP_OPTIONS

/**
 * @def NGX_HTTP_WAF_MODE_INSPECT_PROPFIND
 * @brief 对 PROPFIND 请求进行检查
*/
#define NGX_HTTP_WAF_MODE_INSPECT_PROPFIND                   NGX_HTTP_PROPFIND

/**
 * @def NGX_HTTP_WAF_MODE_INSPECT_PROPPATCH
 * @brief 对 PROPPATCH 请求进行检查
*/
#define NGX_HTTP_WAF_MODE_INSPECT_PROPPATCH                  NGX_HTTP_PROPPATCH

/**
 * @def NGX_HTTP_WAF_MODE_INSPECT_LOCK
 * @brief 对 LOCK 请求进行检查
*/
#define NGX_HTTP_WAF_MODE_INSPECT_LOCK                       NGX_HTTP_LOCK

/**
 * @def NGX_HTTP_WAF_MODE_INSPECT_UNLOCK
 * @brief 对 UNLOCK 请求进行检查
*/
#define NGX_HTTP_WAF_MODE_INSPECT_UNLOCK                     NGX_HTTP_UNLOCK

/**
 * @def NGX_HTTP_WAF_MODE_INSPECT_PATCH
 * @brief 对 PATCH 请求进行检查
*/
#define NGX_HTTP_WAF_MODE_INSPECT_PATCH                      NGX_HTTP_PATCH

/**
 * @def NGX_HTTP_WAF_MODE_INSPECT_TRACE
 * @brief 对 TRACE 请求进行检查
*/
#define NGX_HTTP_WAF_MODE_INSPECT_TRACE                      NGX_HTTP_TRACE

/**
 * @def NGX_HTTP_WAF_MODE_INSPECT_IP
 * @brief 启用 IP 检查规则
*/
#define NGX_HTTP_WAF_MODE_INSPECT_IP                         (NGX_HTTP_WAF_MODE_INSPECT_TRACE << 1)

/**
 * @def NGX_HTTP_WAF_MODE_INSPECT_URL
 * @brief 启用 URL 检查规则
*/
#define NGX_HTTP_WAF_MODE_INSPECT_URL                        (NGX_HTTP_WAF_MODE_INSPECT_IP << 1)

/**
 * @def NGX_HTTP_WAF_MODE_INSPECT_RB
 * @brief 启用 Request Body 检查规则
*/
#define NGX_HTTP_WAF_MODE_INSPECT_RB                         (NGX_HTTP_WAF_MODE_INSPECT_URL << 1)

/**
 * @def NGX_HTTP_WAF_MODE_INSPECT_ARGS
 * @brief 启用 ARGS（GET 请求参数） 检查规则
*/
#define NGX_HTTP_WAF_MODE_INSPECT_ARGS                       (NGX_HTTP_WAF_MODE_INSPECT_RB << 1)

/**
 * @def NGX_HTTP_WAF_MODE_INSPECT_UA
 * @brief 启用 UserAgent 检查规则
*/
#define NGX_HTTP_WAF_MODE_INSPECT_UA                         (NGX_HTTP_WAF_MODE_INSPECT_ARGS << 1)

/**
 * @def NGX_HTTP_WAF_MODE_INSPECT_COOKIE
 * @brief 启用 COOKIE 检查规则
*/
#define NGX_HTTP_WAF_MODE_INSPECT_COOKIE                     (NGX_HTTP_WAF_MODE_INSPECT_UA << 1)

/**
 * @def NGX_HTTP_WAF_MODE_INSPECT_REFERER
 * @brief 启用 Referer 检查规则
*/
#define NGX_HTTP_WAF_MODE_INSPECT_REFERER                    (NGX_HTTP_WAF_MODE_INSPECT_COOKIE << 1)


/**
 * @def NGX_HTTP_WAF_MODE_CMN_METH
 * @brief 常见的请求方法
*/
#define NGX_HTTP_WAF_MODE_CMN_METH               (NGX_HTTP_WAF_MODE_INSPECT_GET          \
                                                | NGX_HTTP_WAF_MODE_INSPECT_POST         \
                                                | NGX_HTTP_WAF_MODE_INSPECT_HEAD)


/**
 * @def NGX_HTTP_WAF_MODE_ALL_METH
 * @brief 所有的
*/
#define NGX_HTTP_WAF_MODE_ALL_METH               (NGX_HTTP_WAF_MODE_INSPECT_GET          \
                                                | NGX_HTTP_WAF_MODE_INSPECT_HEAD         \
                                                | NGX_HTTP_WAF_MODE_INSPECT_POST         \
                                                | NGX_HTTP_WAF_MODE_INSPECT_PUT          \
                                                | NGX_HTTP_WAF_MODE_INSPECT_DELETE       \
                                                | NGX_HTTP_WAF_MODE_INSPECT_MKCOL        \
                                                | NGX_HTTP_WAF_MODE_INSPECT_COPY         \
                                                | NGX_HTTP_WAF_MODE_INSPECT_MOVE         \
                                                | NGX_HTTP_WAF_MODE_INSPECT_OPTIONS      \
                                                | NGX_HTTP_WAF_MODE_INSPECT_PROPFIND     \
                                                | NGX_HTTP_WAF_MODE_INSPECT_PROPPATCH    \
                                                | NGX_HTTP_WAF_MODE_INSPECT_LOCK         \
                                                | NGX_HTTP_WAF_MODE_INSPECT_UNLOCK       \
                                                | NGX_HTTP_WAF_MODE_INSPECT_PATCH        \
                                                | NGX_HTTP_WAF_MODE_INSPECT_TRACE)



/**
 * @def MODE_STD
 * @brief 标准工作模式
*/
#define NGX_HTTP_WAF_MODE_STD                    (NGX_HTTP_WAF_MODE_INSPECT_IP           \
                                                | NGX_HTTP_WAF_MODE_INSPECT_URL          \
                                                | NGX_HTTP_WAF_MODE_INSPECT_RB           \
                                                | NGX_HTTP_WAF_MODE_INSPECT_ARGS         \
                                                | NGX_HTTP_WAF_MODE_INSPECT_UA           \
                                                | NGX_HTTP_WAF_MODE_CMN_METH)
/**
 * @def MODE_STATIC
 * @brief 适用于静态站点的工作模式
*/
#define NGX_HTTP_WAF_MODE_STATIC                 (NGX_HTTP_WAF_MODE_INSPECT_IP           \
                                                | NGX_HTTP_WAF_MODE_INSPECT_URL          \
                                                | NGX_HTTP_WAF_MODE_INSPECT_UA           \
                                                | NGX_HTTP_WAF_MODE_INSPECT_GET          \
                                                | NGX_HTTP_WAF_MODE_INSPECT_HEAD)

/**
 * @def MODE_DYNAMIC
 * @brief 适用于动态站点的工作模式
*/
#define NGX_HTTP_WAF_MODE_DYNAMIC                (NGX_HTTP_WAF_MODE_INSPECT_IP           \
                                                | NGX_HTTP_WAF_MODE_INSPECT_URL          \
                                                | NGX_HTTP_WAF_MODE_INSPECT_RB           \
                                                | NGX_HTTP_WAF_MODE_INSPECT_ARGS         \
                                                | NGX_HTTP_WAF_MODE_INSPECT_UA           \
                                                | NGX_HTTP_WAF_MODE_INSPECT_COOKIE       \
                                                | NGX_HTTP_WAF_MODE_CMN_METH)


/**
 * @def MODE_FULL
 * @brief 启用所有的模式
*/
#define NGX_HTTP_WAF_MODE_FULL                   (UINT64_MAX)

/**
 * @def ngx_http_waf_check_flag(origin, flag)
 * @brief 检查 flag 是否存在于 origin 中，即位操作。
 * @return 存在则返回 NGX_HTTP_WAF_TRUE，反之返回 NGX_HTTP_WAF_FALSE。
 * @retval 非零 存在。
 * @retval 零 不存在。
*/
#define ngx_http_waf_check_flag(origin, flag) (((origin) & (flag)) == (flag))


/**
 * @def ngx_http_waf_check_bit(origin, bit_index)
 * @brief 检查 origin 的某一位是否为 1。
 * @return 如果为一则返回非零
 * @retval 非零 被测试的位为一。
 * @retval 零 被测试的位为零。
 * @note bit_index 从 0 开始计数，其中 0 代表最低位。
*/
#define ngx_http_waf_check_bit(origin, bit_index) (ngx_http_waf_check_flag((origin), 1 << (bit_index)))


#define ngx_http_waf_is_unset_or_disable_value(x) (((x) == NGX_CONF_UNSET) || ((x) == 0))


#define ngx_http_waf_is_empty_str_value(ngx_str_ptr) ((ngx_str_ptr) == NULL || (ngx_str_ptr)->data == NULL || (ngx_str_ptr)->len == 0)


#define ngx_http_waf_is_valid_ptr_value(x) (((x) != NGX_CONF_UNSET_PTR) && ((x) != NULL))


#define ngx_http_waf_make_utarray_ngx_str_icd() { sizeof(ngx_str_t), NULL, ngx_http_waf_utarray_ngx_str_ctor, ngx_http_waf_utarray_ngx_str_dtor }


#define ngx_http_waf_make_utarray_vm_code_icd() { sizeof(vm_code_t), NULL, ngx_http_waf_utarray_vm_code_ctor, ngx_http_waf_utarray_vm_code_dtor }


#define ngx_strdup(s) ((u_char*)strdup((char*)(s)));


#define ngx_strcpy(d, s) (strcpy((char*)d, (const char*)s))


#define ngx_is_null_str(s) ((s) == NULL || (s)->data == NULL || (s)->len == 0 || ((s)->data[0] == '\0' && (s)->len == 1))


#ifndef NGX_HTTP_WAF_NO_DEBUG
#define ngx_http_waf_dp_func_start(r) { \
    if (r != NULL) { \
        ngx_http_waf_dpf(r, "%s start", __func__); \
    } \
}


#define ngx_http_waf_dp(r, str) { \
    if (r != NULL) {    \
        ngx_log_error(NGX_LOG_DEBUG, (r)->connection->log, 0,  \
            "ngx_waf_debug: ["str"] at %s:%s:%d, ngx_waf %s", __func__, __FILE__, __LINE__, NGX_HTTP_WAF_VERSION); \
    } \
}


#define ngx_http_waf_dpf(r, fmt, ...) { \
    if (r != NULL) {    \
        ngx_log_error(NGX_LOG_DEBUG, (r)->connection->log, 0,  \
            "ngx_waf_debug: ["fmt"] at %s:%s:%d, ngx_waf %s", __VA_ARGS__, __func__, __FILE__, __LINE__, NGX_HTTP_WAF_VERSION); \
    }  \
}


#define ngx_http_waf_dp_func_end(r) { \
    if (r != NULL) { \
        ngx_http_waf_dpf(r, "%s end", __func__); \
    } \
}
#else
#define ngx_http_waf_dp_func_start(...) {}


#define ngx_http_waf_dp(...) {}


#define ngx_http_waf_dpf(...) {}


#define ngx_http_waf_dp_func_end(...) {}
#endif


#endif // !NGX_HTTP_WAF_MODULE_MACRO_H
