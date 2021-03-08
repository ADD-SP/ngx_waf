/**
 * @file ngx_http_waf_module_macro.h
 * @brief 定义一些必要的宏
*/

#ifndef NGX_HTTP_WAF_MODULE_MACRO_H
#define NGX_HTTP_WAF_MODULE_MACRO_H

/* 对应配置文件的文件名 */
#define IPV4_FILE               ("ipv4")
#define IPV6_FILE               ("ipv6")
#define URL_FILE                ("url")
#define ARGS_FILE               ("args")
#define UA_FILE                 ("user-agent")
#define REFERER_FILE            ("referer")
#define COOKIE_FILE             ("cookie")
#define POST_FILE               ("post")
#define WHITE_IPV4_FILE         ("white-ipv4")
#define WHITE_IPV6_FILE         ("white-ipv6")
#define WHITE_URL_FILE          ("white-url")
#define WHITE_REFERER_FILE      ("white-referer")


#ifndef FALSE
#define FALSE                   (0)
#endif

#ifndef FAIL
#define FAIL                    (0)
#endif

#ifndef NOT_MATCHED
#define NOT_MATCHED             (0)
#endif

#ifndef TRUE
#define TRUE                    (1)
#endif

#ifndef SUCCESS
#define SUCCESS                 (1)
#endif

#ifndef MATCHED
#define MATCHED                 (1)
#endif

#ifndef PROCESSING
#define PROCESSING              (2)
#endif

#ifndef MALLOC_ERROR
#define MALLOC_ERROR            (3)
#endif


/**
 * @def RULE_MAX_LEN
 * @brief 每条规则的占用的最大字节数。
*/
#define RULE_MAX_LEN            (256 * 4 * 8)

/**
 * @def INITIAL_SIZE
 * @brief 初始化配置块内存池时的初始内存池大小。
*/
#define INITIAL_SIZE            (1024 * 1024 * 5)

#define MAX_ALLOC_TIMES         (100000)

/**
 * @def SHARE_MEMORY_NAME
 * @brief 用于 CC 防护的共享内存的名称
*/
#define SHARE_MEMORY_NAME       ("__ADD-SP_NGX_WAF__")

/**
 * @def INITIAL_SIZE
 * @brief 用于 CC 防护的共享内存的大小（字节）
*/
#define SHATE_MEMORY_MIN_SIZE   (1024 * 1024 * 10)

/**
 * @def MODE_INSPECT_GET
 * @brief 对 GET 请求进行检查
*/
#define MODE_INSPECT_GET                        NGX_HTTP_GET

/**
 * @def MODE_INSPECT_HEAD
 * @brief 对 HEAD 请求进行检查
*/
#define MODE_INSPECT_HEAD                       NGX_HTTP_HEAD

/**
 * @def MODE_INSPECT_POST
 * @brief 对 POST 请求进行检查
*/
#define MODE_INSPECT_POST                       NGX_HTTP_POST

/**
 * @def MODE_INSPECT_PUT
 * @brief 对 PUT 请求进行检查
*/
#define MODE_INSPECT_PUT                        NGX_HTTP_PUT

/**
 * @def MODE_INSPECT_DELETE
 * @brief 对 DELETE 请求进行检查
*/
#define MODE_INSPECT_DELETE                     NGX_HTTP_DELETE

/**
 * @def MODE_INSPECT_MKCOL
 * @brief 对 MKCOL 请求进行检查
*/
#define MODE_INSPECT_MKCOL                      NGX_HTTP_MKCOL

/**
 * @def MODE_INSPECT_COPY
 * @brief 对 COPY 请求进行检查
*/
#define MODE_INSPECT_COPY                       NGX_HTTP_COPY

/**
 * @def MODE_INSPECT_MOVE
 * @brief 对 MOVE 请求进行检查
*/
#define MODE_INSPECT_MOVE                       NGX_HTTP_MOVE

/**
 * @def MODE_INSPECT_OPTIONS
 * @brief 对 OPTIONS 请求进行检查
*/
#define MODE_INSPECT_OPTIONS                    NGX_HTTP_OPTIONS

/**
 * @def MODE_INSPECT_PROPFIND
 * @brief 对 PROPFIND 请求进行检查
*/
#define MODE_INSPECT_PROPFIND                   NGX_HTTP_PROPFIND

/**
 * @def MODE_INSPECT_PROPPATCH
 * @brief 对 PROPPATCH 请求进行检查
*/
#define MODE_INSPECT_PROPPATCH                  NGX_HTTP_PROPPATCH

/**
 * @def MODE_INSPECT_LOCK
 * @brief 对 LOCK 请求进行检查
*/
#define MODE_INSPECT_LOCK                       NGX_HTTP_LOCK

/**
 * @def MODE_INSPECT_UNLOCK
 * @brief 对 UNLOCK 请求进行检查
*/
#define MODE_INSPECT_UNLOCK                     NGX_HTTP_UNLOCK

/**
 * @def MODE_INSPECT_PATCH
 * @brief 对 PATCH 请求进行检查
*/
#define MODE_INSPECT_PATCH                      NGX_HTTP_PATCH

/**
 * @def MODE_INSPECT_TRACE
 * @brief 对 TRACE 请求进行检查
*/
#define MODE_INSPECT_TRACE                      NGX_HTTP_TRACE

/**
 * @def MODE_INSPECT_IP
 * @brief 启用 IP 检查规则
*/
#define MODE_INSPECT_IP                         (MODE_INSPECT_TRACE << 1)

/**
 * @def MODE_INSPECT_URL
 * @brief 启用 URL 检查规则
*/
#define MODE_INSPECT_URL                        (MODE_INSPECT_IP << 1)

/**
 * @def MODE_INSPECT_RB
 * @brief 启用 Request Body 检查规则
*/
#define MODE_INSPECT_RB                         (MODE_INSPECT_URL << 1)

/**
 * @def MODE_INSPECT_ARGS
 * @brief 启用 ARGS（GET 请求参数） 检查规则
*/
#define MODE_INSPECT_ARGS                       (MODE_INSPECT_RB << 1)

/**
 * @def MODE_INSPECT_UA
 * @brief 启用 UserAgent 检查规则
*/
#define MODE_INSPECT_UA                         (MODE_INSPECT_ARGS << 1)

/**
 * @def MODE_INSPECT_COOKIE
 * @brief 启用 COOKIE 检查规则
*/
#define MODE_INSPECT_COOKIE                     (MODE_INSPECT_UA << 1)

/**
 * @def MODE_INSPECT_REFERER
 * @brief 启用 Referer 检查规则
*/
#define MODE_INSPECT_REFERER                    (MODE_INSPECT_COOKIE << 1)

/**
 * @def MODE_INSPECT_CC
 * @brief 启用 CC 防御
*/
#define MODE_INSPECT_CC                         (MODE_INSPECT_REFERER << 1)

/**
 * @def MODE_STD
 * @brief 标准工作模式
*/
#define MODE_STD                                (MODE_INSPECT_IP            \
                                                | MODE_INSPECT_URL          \
                                                | MODE_INSPECT_RB           \
                                                | MODE_INSPECT_ARGS         \
                                                | MODE_INSPECT_UA           \
                                                | MODE_INSPECT_HEAD         \
                                                | MODE_INSPECT_GET          \
                                                | MODE_INSPECT_POST         \
                                                | MODE_INSPECT_CC)
/**
 * @def MODE_STD
 * @brief 适用于静态站点的工作模式
*/
#define MODE_STATIC                             (MODE_INSPECT_IP            \
                                                | MODE_INSPECT_URL          \
                                                | MODE_INSPECT_UA           \
                                                | MODE_INSPECT_GET          \
                                                | MODE_INSPECT_HEAD         \
                                                | MODE_INSPECT_CC)

/**
 * @def MODE_STD
 * @brief 适用于动态站点的工作模式
*/
#define MODE_DYNAMIC                            (MODE_INSPECT_IP            \
                                                | MODE_INSPECT_URL          \
                                                | MODE_INSPECT_RB           \
                                                | MODE_INSPECT_ARGS         \
                                                | MODE_INSPECT_UA           \
                                                | MODE_INSPECT_COOKIE       \
                                                | MODE_INSPECT_HEAD         \
                                                | MODE_INSPECT_GET          \
                                                | MODE_INSPECT_POST         \
                                                | MODE_INSPECT_CC)


/**
 * @def MODE_FULL
 * @brief 检测全部请求类型并启用全部的检测项目
*/
#define MODE_FULL                               (MODE_INSPECT_IP            \
                                                | MODE_INSPECT_URL          \
                                                | MODE_INSPECT_RB           \
                                                | MODE_INSPECT_ARGS         \
                                                | MODE_INSPECT_UA           \
                                                | MODE_INSPECT_COOKIE       \
                                                | MODE_INSPECT_REFERER      \
                                                | MODE_INSPECT_GET          \
                                                | MODE_INSPECT_POST         \
                                                | MODE_INSPECT_HEAD         \
                                                | MODE_INSPECT_PUT          \
                                                | MODE_INSPECT_DELETE       \
                                                | MODE_INSPECT_MKCOL        \
                                                | MODE_INSPECT_COPY         \
                                                | MODE_INSPECT_PROPFIND     \
                                                | MODE_INSPECT_PROPPATCH    \
                                                | MODE_INSPECT_LOCK         \
                                                | MODE_INSPECT_UNLOCK       \
                                                | MODE_INSPECT_PATCH        \
                                                | MODE_INSPECT_TRACE        \
                                                | MODE_INSPECT_CC)



#ifndef min
/**
 * @def min(a,b)
*/
#define min(a,b)            (((a) < (b)) ? (a) : (b))
#endif

#ifndef max
/**
 * @def max(a,b)
*/
#define max(a,b)            (((a) > (b)) ? (a) : (b))
#endif


/* 检查对应文件是否存在，如果存在则根据 mode 的值将数据处理后存入容器中 */
/** 
 * @def CHECK_AND_LOAD_CONF(cf, folder, end, filename, container, mode)
 * @brief 检查对应文件是否存在，如果存在则根据 mode 的值将数据处理后存入数组中。
 * @param[in] folder 配置文件所在文件夹的绝对路径。
 * @param[in] end folder 字符数组的 '\0' 的地址。
 * @param[in] filename 配置文件名。
 * @param[out] container 存储配置读取结果的容器。
 * @param[in] mode 配置读取模式。
 * @warning 当文件不存在的时候会直接执行 @code return  NGX_CONF_ERROR; @endcode 语句。
*/
#define CHECK_AND_LOAD_CONF(cf, folder, end, filename, container, mode) {                                       \
    strcat((folder), (filename));                                                                               \
    if (access((folder), R_OK) != 0) {                                                                             \
        ngx_conf_log_error(NGX_LOG_ERR, (cf), 0, "ngx_waf: %s: %s", (folder), "No such file or directory");     \
        return NGX_CONF_ERROR;                                                                                  \
    }                                                                                                           \
    if (load_into_container((cf), (folder), (container), (mode)) == FAIL) {                                     \
        ngx_conf_log_error(NGX_LOG_ERR, (cf), 0, "ngx_waf: %s: %s", (folder), "Cannot read configuration.");    \
        return NGX_CONF_ERROR;                                                                                  \
    }                                                                                                           \
    *(end) = '\0';                                                                                              \
}

/**
 * @def CHECK_FLAG(origin, flag)
 * @brief 检查 flag 是否存在于 origin 中，即位操作。
 * @return 存在则返回 TRUE，反之返回 FALSE。
 * @retval TRUE 存在。
 * @retval FALSE 不存在。
*/
#define CHECK_FLAG(origin, flag) (((origin) & (flag)) != 0 ? TRUE : FALSE)


/**
 * @def CHECK_BIT(origin, bit_index)
 * @brief 检查 origin 的某一位是否为 1。
 * @return 如果为一则返回 TRUE，反之返回 FALSE。
 * @retval TRUE 被测试的位为一。
 * @retval FALSE 被测试的位为零。
 * @note bit_index 从 0 开始计数，其中 0 代表最低位。
*/
#define CHECK_BIT(origin, bit_index) (CHECK_FLAG((origin), 1 << (bit_index)))


#endif // !NGX_HTTP_WAF_MODULE_MACRO_H
