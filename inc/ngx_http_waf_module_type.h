/**
 * @file ngx_http_waf_module_type.h
 * @brief 相关结构体的定义
*/


#ifndef __NGX_HTTP_WAF_MODULE_TYPE_H__
#define __NGX_HTTP_WAF_MODULE_TYPE_H__

#include <uthash.h>
#include <utarray.h>
#include <utlist.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_regex.h>
#include <ngx_inet.h>
#include <ngx_thread.h>
#include <ngx_thread_pool.h>
#include <ngx_http_waf_module_macro.h>
#include <sodium.h>
#include <modsecurity/modsecurity.h>
#include <modsecurity/transaction.h>

#if defined(MODSECURITY_CHECK_VERSION)
#if MODSECURITY_VERSION_NUM >= 304010
#define MSC_USE_RULES_SET 1
#endif
#endif

#if defined(MSC_USE_RULES_SET)
#include <modsecurity/rules_set.h>
#else
#include <modsecurity/rules.h>
#endif


/**
 * @typedef ngx_http_waf_check
 * @brief 请求检查函数的函数指针
*/
typedef ngx_int_t (*ngx_http_waf_check_pt)(ngx_http_request_t* r);


/**
 * @struct inx_addr_t
 * @brief 代表 ipv4 或 ipv6 地址。
*/
typedef union inx_addr_u {
    struct in_addr  ipv4;
#if (NGX_HAVE_INET6)
    struct in6_addr ipv6;
#endif
} inx_addr_t;


/**
 * @struct singly_linked_list_t
 * @brief 单链表
*/
typedef struct singly_linked_list_s {
    void                               *data;               /**< 链表的数据项 */
    size_t                              data_byte_length;   /**< data 指针指向的内存的长度（字节） */
    struct singly_linked_list_s        *next;               /**< utlist 关键成员 */
} singly_linked_list_t;


/**
 * @struct circular_doublly_linked_list_t
 * @brief 双向循环链表
*/
typedef struct circular_doublly_linked_list_s {
    void                                       *data;               /**< 链表的数据项 */
    size_t                                      data_byte_length;   /**< data 指针指向的内存的长度（字节） */
    struct circular_doublly_linked_list_s      *prev;               /**< utlist 关键成员 */
    struct circular_doublly_linked_list_s      *next;               /**< utlist 关键成员 */
} circular_doublly_linked_list_t;


/**
 * @struct ip_statis_t
 * @brief 用于记录 CC 防护信息
*/
typedef struct ip_statis_s {
    ngx_int_t       count;              /**< 访问次数 */
    ngx_int_t       is_blocked;         /**< 是否已经被拦截 */
    time_t          record_time;        /**< 何时开始记录 */
    time_t          block_time;         /**< 何时开始拦截 */
} ip_statis_t;


/**
 * @struct check_result_t
 * @brief 规则减价结果
*/
typedef struct check_result_s {
    ngx_int_t       is_matched;         /**< 是否被某条规则匹配到 */
    u_char         *detail;             /**< 匹配到的规则的详情 */
} check_result_t;


/**
 * @struct key_value_t
 * @brief 哈希表（字符串 -> 字符串）
*/
typedef struct key_value_s {
    ngx_str_t           key;        /**< 键 */   
    ngx_str_t           value;      /**< 值 */
    UT_hash_handle      hh;         /**< uthash 关键成员 */
} key_value_t;


/**
 * @enum memory_pool_type_e
 * @brief 内存池类型
*/
typedef enum {
    MEM_POOL_FLAG_UNSET     = 0,    /**< 未设置 */
    MEM_POOL_FLAG_STDC      = 1,    /**< 基于 malloc 的内存池 */
    MEM_POOL_FLAG_NGX       = 2,    /**< 基于 ngx_pool_t 的内存池 */
    MEM_POOL_FLAG_NGX_SHARD = 4,    /**< 基于 ngx_slab_t 的内存池 */
    MEM_POOL_FLAG_FIXED     = 8     /**< 固定大小的内存池 */
} mem_pool_flag_e;


/**
 * @struct mem_pool_t
 * @brief 包含常规内存池或 slab 内存池
*/
typedef struct mem_pool_s {
    mem_pool_flag_e                     flag;                   /**< 标识内存池的类型 */
    size_t                              capacity;               /**< 内存池的容量 */
    size_t                              used;                   /**< 已使用的内存量（字节） */
    void*                               native_pool;
} mem_pool_t;


typedef struct shm_s shm_t;


typedef ngx_int_t (*shm_init_pt)(shm_t* shm, void* data, void* old_data);

/** 垃圾收集函数 */
typedef ngx_int_t (*shm_gc_pt)(shm_t* shm, void* data, ngx_int_t* low_memory);


typedef struct shm_init_s {
    shm_init_pt init_handler;
    shm_gc_pt  gc_handler;
    void* data;
    ngx_str_t tag;
    struct shm_init_s* next;
} shm_init_t;


typedef struct shm_s {
    ngx_shm_zone_t* zone;
    ngx_conf_t* cf;
    ngx_str_t name;
    size_t size;
    shm_init_t* init_chain;
    mem_pool_t* pool;
} shm_t;



/**
 * @struct lru_cache_result_t
 * @brief LRU 操作结果
*/
typedef struct lru_cache_result_s {
    int status;
    void **data;
} lru_cache_result_t;


typedef lru_cache_result_t lru_cache_add_result_t;

typedef lru_cache_result_t lru_cache_find_result_t;


/**
 * @struct lru_cache_item_t
 * @brief LRU 缓存项
*/
typedef struct lru_cache_item_s {
    u_char                             *key_ptr;            /**< 用于哈希的关键字 */
    size_t                              key_byte_length;    /**< 关键字占用的字节数 */
    time_t                              expire;             /**< 过期时间（秒） */
    void                               *data;               /**< 缓存项的具体数据 */
    struct lru_cache_item_s            *prev;               /**< utlist 关键成员 */
    struct lru_cache_item_s            *next;               /**< utlist 关键成员 */
    UT_hash_handle                      hh;                 /**< uthash 关键成员 */
} lru_cache_item_t;


/**
 * @struct lru_cache_t
 * @brief LRU 缓存管理器
*/
typedef struct lru_cache_s {
    time_t                            last_eliminate;     /**< 最后一次批量淘汰缓存的时间 */
    mem_pool_t                       *pool;               /**< 内存池 */
    size_t                            capacity;           /**< 最多嫩容纳多少个缓存项 */
    lru_cache_item_t                 *hash_head;          /**< uthash 的表头 */
    lru_cache_item_t                 *chain_head;         /**< utlist 的表头 */
    ngx_int_t                         no_memory:1;        /**< 近期是否触发惰性淘汰 */
} lru_cache_t;


/**
 * @struct ip_trie_node_t
 * @brief 前缀树节点。
*/
typedef struct ip_trie_node_s {
    int                     is_ip;          /**< 如果为 TRUE 则代表此节点也代表一个 IP，反之则为 FALSE */
    struct ip_trie_node_s  *left;           /**< 左子树代表当前位为零 */
    struct ip_trie_node_s  *right;          /**< 右子树代表当前位为一 */
    void                   *data;
    size_t                  data_byte_length;
} ip_trie_node_t;


/**
 * @struct ip_trie_t
 * @brief 前缀树。
*/
typedef struct ip_trie_s {
    int                 ip_type;        /**< 存储的 IP 地址的类型。 */
    ip_trie_node_t     *root;           /**< 前缀树树根。 */
    int                 match_all;      /**< 当遇到前缀长度为零（0.0.0.0/0）的地址时为真，代表所有查询均返回真。 */
    size_t              size;           /**< 已经存储的 IP 数量。 */
    mem_pool_t         *pool;           /**< 使用的内存池 */
} ip_trie_t;


typedef enum {
    BOT_TYPE_NONE       = 0X0,
    BOT_TYPE_UNSET      = 0X1,
    BOT_TYPE_GOOGLE     = 0X2,
    BOT_TYPE_BING       = 0X4,
    BOT_TYPE_BAIDU      = 0X8,
    BOT_TYPE_SOGOU      = 0X10,
    BOT_TYPE_YANDEX     = 0X20
} bot_type_e;


typedef enum {
    ACTION_FLAG_NONE                = 0x0,
    ACTION_FLAG_UNSET               = 0x1,
    ACTION_FLAG_DECLINE             = 0x2,
    ACTION_FLAG_DONE                = 0x4,
    ACTION_FLAG_FOLLOW              = 0x8,
    ACTION_FLAG_RETURN              = 0x10,
    ACTION_FLAG_INTERNAL_REDIRECT   = 0x20,
    ACTION_FLAG_REG_CONTENT         = 0x40,
    ACTION_FLAG_STR                 = 0x80,
    ACTION_FLAG_HTML                = 0x100,
    ACTION_FLAG_FROM_WHITE_LIST     = 0x200,
    ACTION_FLAG_FROM_BLACK_LIST     = 0x400,
    ACTION_FLAG_FROM_CC_DENY        = 0x800,
    ACTION_FLAG_FROM_MODSECURITY    = 0x1000,
    ACTION_FLAG_FROM_CAPTCHA        = 0x2000,
    ACTION_FLAG_FROM_UNDER_ATTACK   = 0x4000,
    ACTION_FLAG_FROM_VERIFY_BOT     = 0x8000,
    ACTION_FLAG_FROM_SYSGUARD       = 0x10000,
    ACTION_FLAG_FROM_SYSGUARD_LOAD  = 0x20000,
    ACTION_FLAG_FROM_SYSGUARD_MEM   = 0x40000,
    ACTION_FLAG_FROM_SYSGUARD_SWAP  = 0x80000,
    ACTION_FLAG_CAPTCHA             = 0x100000,
    ACTION_FLAG_UNDER_ATTACK        = 0X200000,
} action_flag_e;


typedef struct action_s {
    action_flag_e flag;
    struct action_s* next;
    struct action_s* prev;
    union {
        ngx_uint_t http_status;

        struct {
            ngx_uint_t http_status;
            ngx_str_t* str;
        } extra_str;

        struct {
            ngx_uint_t http_status;
            ngx_str_t* html;
        } extra_html;

        struct {
            ngx_str_t* uri;
            ngx_str_t* args;
        } extra_internal_redirect;

    } extra;
} action_t;


/**
 * @struct ngx_http_waf_ctx_t
 * @brief 每个请求的上下文
*/
typedef struct ngx_http_waf_ctx_s {
    ngx_http_request_t*             r;
    Transaction                    *modsecurity_transaction;                    /**< ModSecurity 的事务 */
    ngx_str_t                       rule_type;                                  /**< 触发的规则类型 */                         
    ngx_str_t                       rule_deatils;                               /**< 触发的规则内容 */
    ngx_buf_t                       req_body;                                   /**< 请求体 */
    ngx_int_t                       rate;                                       /**< 对应变量 $waf_rate */
    double                          spend;                                      /**< 本次检查花费的时间（毫秒） */
    char                           *response_str;                               /**< 如果不为 NULL 则返回所指的字符串和 200 状态码 */
    action_t                       *action_chain;
#if (NGX_THREADS) && (NGX_HTTP_WAF_ASYNC_MODSECURITY)
    ngx_int_t                       modsecurity_status;                         /**< ModSecurity 规则所返回的 HTTP 状态码 */
    ngx_int_t                       modsecurity_triggered;                      /**< 是否触发了 ModSecurity 的规则 */
    ngx_int_t                       start_from_thread;                          /**< 是否是从 ModSecurity 的线程中被启动 */
#endif
    ngx_int_t                       handler_index;                              /**< 当前处理函数的索引 */
#if (NGX_THREADS) 
    ngx_int_t                       async_captcha:1;                            /**< 是否完成了对 CAPTCHA API 的异步请求 */
    ngx_int_t                       async_captcha_pass:1;                       /**< CAPTCHA API 的异步请求验证否通过 */
#endif
    ngx_int_t                       pre_content_run:1;                          /**< 是否已经执行过 pre_content handler */
    ngx_int_t                       gernal_logged:1;                            /**< 是否需要记录除 ModSecurity 以外的记录日志 */
    ngx_int_t                       checked:1;                                  /**< 是否启动了检测流程 */
    ngx_int_t                       blocked:1;                                  /**< 是否拦截了本次请求 */
    ngx_int_t                       read_body_done:1;                           /**< 是否已经请求读取请求体 */
    ngx_int_t                       waiting_more_body:1;                        /**< 是否等待读取更多请求体 */
    ngx_int_t                       has_req_body:1;                             /**< 字段 req_body 是否以己经存储了请求体 */
    ngx_int_t                       register_content_handler:1;                 /**< 是否已经注册或应该注册内容处理程序 */
} ngx_http_waf_ctx_t;


/**
 * @struct ngx_http_waf_main_conf_t
 * @brief http 块配置项
*/
typedef struct ngx_http_waf_main_conf_s {
    ngx_array_t                    *shms;                                       /**< 共享内存列表 */
    ngx_array_t                    *local_caches;                               /**< 未使用共享内存的缓存列表 */
#if (NGX_THREADS)
    ngx_thread_pool_t              *thread_pool_network;                        /**< 用于网络请求的线程池 */
#endif
} ngx_http_waf_main_conf_t;


/**
 * @struct ngx_http_waf_loc_conf_t
 * @brief 每个 server 块的配置块
*/
typedef struct ngx_http_waf_loc_conf_s {
    struct ngx_http_waf_loc_conf_s *parent;                                     /**< 上层配置，用来定位 CC 防护所使用的共享内存 */
    u_char                          random_str[129];                            /**< 随机字符串 */
    ngx_int_t                       is_alloc;                                   /**< 是否已经分配的存储规则的容器的内存 */
    ngx_int_t                       waf;                                        /**< 0: 禁用, 1 启用, 2 旁路模式 */
    ngx_str_t                       waf_rule_path;                              /**< 配置文件所在目录 */  
    uint64_t                        waf_mode;                                   /**< 检测模式 */
    ngx_int_t                       waf_cc_deny;                                /**< 0 为关闭，1 超出限制拉黑，2 超出限制弹出验证码三次，三次均失败则拉黑 */
    ngx_int_t                       waf_cc_deny_limit;                          /**< CC 防御的限制频率 */
    ngx_int_t                       waf_cc_deny_duration;                       /**< CC 防御的拉黑时长（秒） */
    ngx_int_t                       waf_cc_deny_cycle;                          /**< CC 防御的统计周期（秒） */
    ngx_int_t                       waf_cache;                                  /**< 是否启用缓存 */
    ngx_int_t                       waf_cache_capacity;                         /**< 用于缓存检查结果的共享内存的大小（字节） */
    ngx_int_t                       waf_verify_bot;                             /**< 0: 禁用, 1 仅放行真爬虫, 2: 拦截假爬虫 */
    ngx_int_t                       waf_verify_bot_type;                        /**< 位图，表示检测哪些 Bot */
    ngx_array_t                    *waf_verify_bot_google_ua_regexp;            /**< Googlebot 的合法 User-Agent */
    ngx_array_t                    *waf_verify_bot_bing_ua_regexp;              /**< Bingbot 的合法 User-Agent */
    ngx_array_t                    *waf_verify_bot_baidu_ua_regexp;             /**< BaiduSpider 的合法 User-Agent */
    ngx_array_t                    *waf_verify_bot_yandex_ua_regexp;            /**< Yandexbot 的合法 User-Agent */
    ngx_array_t                    *waf_verify_bot_sogou_ua_regexp;             /**< SogouSpider 的合法 User-Agent */
    ngx_array_t                    *waf_verify_bot_google_domain_regexp;        /**< Googlebot 的合法的主机名 */
    ngx_array_t                    *waf_verify_bot_bing_domain_regexp;          /**< Bingbot 的合法的主机名 */
    ngx_array_t                    *waf_verify_bot_baidu_domain_regexp;         /**< BaiduSpider 的合法的主机名 */
    ngx_array_t                    *waf_verify_bot_yandex_domain_regexp;        /**< Yandexbot 的合法的主机名 */
    ngx_array_t                    *waf_verify_bot_sogou_domain_regexp;         /**< SogouSpider 的合法的主机名 */
    ngx_int_t                       waf_under_attack;                           /**< 是否启用五秒盾 */
    ngx_str_t                       waf_under_attack_html;                      /**< 五秒盾的 HTML 数据 */
    ngx_int_t                       waf_captcha;                                /**< 是否启用验证码 */
    ngx_int_t                       waf_captcha_type;                           /**< 验证码的类型 */
    ngx_str_t                       waf_captcha_hCaptcha_secret;                /**< hCaptcha 的 secret */
    ngx_str_t                       waf_captcha_reCAPTCHAv2_secret;             /**< Google reCPATCHA 的 secret */
    ngx_str_t                       waf_captcha_reCAPTCHAv3_secret;             /**< Google reCPATCHA 的 secret */
    double                          waf_captcha_reCAPTCHAv3_score;              /**< Google reCAPTCHAv3 的下限分数 */
    ngx_str_t                       waf_captcha_api;                            /**< 验证码提供商的 API */
    ngx_str_t                       waf_captcha_verify_url;                     /**< 本模块接管的用于验证的 URL */
    ngx_int_t                       waf_captcha_expire;                         /**< 验证码的有效期 */
    ngx_str_t                       waf_captcha_html;                           /**< 验证码页面的 HTML 数据 */
    ngx_int_t                       waf_captcha_max_fails;                      /**< 验证码的最大失败次数 */
    ngx_int_t                       waf_captcha_duration;                       /**< 验证码的拉黑时长（秒） */
    ngx_shm_zone_t                 *waf_captcha_shm_zone;                       /**< 验证码的共享内存 */
    lru_cache_t                    *waf_captcha_cache;                          /**< 验证码的 LRU 缓存 */
    ngx_int_t                       waf_modsecurity;                            /**< 是否启用 ModSecurity */
    ngx_str_t                       waf_modsecurity_rules_file;                 /**< ModSecurity 规则文件的绝对路径 */
    ngx_str_t                       waf_modsecurity_rules_remote_key;
    ngx_str_t                       waf_modsecurity_rules_remote_url;
    ngx_http_complex_value_t*       waf_modsecurity_transaction_id;
    ngx_str_t                       waf_block_page;                             /**< 封禁页面的 HTML */
    ngx_int_t                       waf_sysguard;                               /**< 是否启用系统状态检测 */
    ngx_int_t                       waf_sysguard_interval;                      /**< 系统状态检测的间隔（秒） */
    double                          waf_sysguard_load_threshold;                /**< 系统负载阈值 */
    double                          waf_sysguard_mem_threshold;                 /**< 内存阈值 */
    double                          waf_sysguard_swap_threshold;                /**< 交换空间阈值 */
    action_t                       *action_chain_blacklist;                     /**< 黑名单触发后的动作 */
    action_t                       *action_chain_cc_deny;                       /**< CC 触发后的动作 */
    action_t                       *action_chain_modsecurity;                   /**< ModSecurity 触发后的动作 */
    action_t                       *action_chain_verify_bot;                    /**< verify_bot 触发后的动作 */
    action_t                       *action_chain_sysguard_load;                 /**< sysguard_load 触发后的动作 */
    action_t                       *action_chain_sysguard_mem;                  /**< sysguard_mem 触发后的动作 */
    action_t                       *action_chain_sysguard_swap;                 /**< sysguard_swap 触发后的动作 */
    ngx_shm_zone_t                 *action_zone_captcha;                        /**< 验证码动作使用的 zone */
    lru_cache_t                    *action_cache_captcha;                       /**< 验证码动作使用的 cache */
    ModSecurity                    *modsecurity_instance;                       /**< ModSecurity 实例 */
    void                           *modsecurity_rules;                          /**< ModSecurity 规则容器 */

    ngx_int_t                       base_rules_id;                              /**< 
                                                                                     基础规则的 ID 
                                                                                     基础规则就是所有的黑白名单规则
                                                                                     每次读取完所有的基础规则后都会生成一个唯一的 ID
                                                                                     这个 ID 将用于合并不同层级的缓存配置
                                                                                     防止不同的基础规则使用同一个缓存空间引起混乱     
                                                                                */

    ip_trie_t                      *black_ipv4;                                 /**< IPV4 黑名单 */
#if (NGX_HAVE_INET6)
    ip_trie_t                      *black_ipv6;                                 /**< IPV6 黑名单 */
#endif
    ngx_array_t                    *black_url;                                  /**< URL 黑名单 */
    ngx_array_t                    *black_args;                                 /**< args 黑名单 */
    ngx_array_t                    *black_ua;                                   /**< user-agent 黑名单 */
    ngx_array_t                    *black_referer;                              /**< Referer 黑名单 */
    ngx_array_t                    *black_cookie;                               /**< Cookie 黑名单 */
    ngx_array_t                    *black_header;                               /**< Header 黑名单 */
    ngx_array_t                    *black_post;                                 /**< 请求体内容黑名单 */

    ip_trie_t                      *white_ipv4;                                 /**< IPV4 白名单 */
#if (NGX_HAVE_INET6)
    ip_trie_t                      *white_ipv6;                                 /**< IPV6 白名单 */
#endif
    ngx_array_t                    *white_url;                                  /**< URL 白名单 */
    ngx_array_t                    *white_args;                                 /**< args 白名单 */
    ngx_array_t                    *white_ua;                                   /**< user-agent 白名单 */
    ngx_array_t                    *white_referer;                              /**< Referer 白名单 */
    ngx_array_t                    *white_cookie;                               /**< Cookie 白名单 */
    ngx_array_t                    *white_header;                               /**< Header 白名单 */
    ngx_array_t                    *white_post;                                 /**< 请求体内容白名单 */

    ngx_shm_zone_t                 *shm_zone_cc_deny;                           /**< 共享内存 */
    lru_cache_t                    *ip_access_statistics;                       /**< IP 访问频率统计表 */
    lru_cache_t                    *black_url_inspection_cache;                 /**< URL 黑名单检查缓存 */
    lru_cache_t                    *black_args_inspection_cache;                /**< ARGS 黑名单检查缓存 */
    lru_cache_t                    *black_ua_inspection_cache;                  /**< User-Agent 黑名单检查缓存 */
    lru_cache_t                    *black_referer_inspection_cache;             /**< Referer 黑名单检查缓存 */
    lru_cache_t                    *black_cookie_inspection_cache;              /**< Cookie 黑名单检查缓存 */
    lru_cache_t                    *black_header_inspection_cache;              /**< Header 黑名单检查缓存 */
    lru_cache_t                    *white_url_inspection_cache;                 /**< URL 白名单检查缓存 */
    lru_cache_t                    *white_args_inspection_cache;                /**< ARGS 白名单检查缓存 */
    lru_cache_t                    *white_ua_inspection_cache;                  /**< User-Agent 白名单检查缓存 */
    lru_cache_t                    *white_referer_inspection_cache;             /**< Referer 白名单检查缓存 */
    lru_cache_t                    *white_cookie_inspection_cache;              /**< Cookie 白名单检查缓存 */
    lru_cache_t                    *white_header_inspection_cache;              /**< Header 白名单检查缓存 */
#if (NGX_THREADS) && (NGX_HTTP_WAF_ASYNC_MODSECURITY)
    ngx_thread_pool_t              *thread_pool;
#endif
    ngx_int_t                       is_custom_priority;                         /**< 用户是否自定义了优先级 */
    ngx_int_t                       is_custom_cache;                            /**< 用户是否使用了指令 waf_cache */
    ngx_http_waf_check_pt           check_proc[30];                             /**< 各种检测流程的启动函数 */
} ngx_http_waf_loc_conf_t;


/**
 * @struct ipv4_t
 * @brief 格式化后的 IPV4
 * @note 注意，无论是 prefix 还是 suffix 都是网络字节序，即大端字节序。
*/
typedef struct ipv4_s {
    u_char                          text[32];       /**< 点分十进制表示法 */
    uint32_t                        prefix;         /**< 相当于 192.168.1.0/24 中的 192.168.1.0 的整数形式 */
    uint32_t                        suffix;         /**< 相当于 192.168.1.0/24 中的 24 的位表示（网络字节序） */
    uint32_t                        suffix_num;     /**< 相当于 192.168.1.0/24 中的 24 */
} ipv4_t;


/**
 * @struct ipv6_t
 * @brief 格式化后的 IPV6
 * @note 注意，无论是 prefix[16] 还是 suffix[16]，他们中的每一项都是网络字节序。
 * 数组的下标同理，下标零代表最高位，下标十五代表最低位。
*/
#if (NGX_HAVE_INET6)
typedef struct ipv6_s {
    u_char                          text[64];       /**< 冒号十六进制表示法 */
    uint8_t                         prefix[16];     /**< 相当于 ffff::ffff/64 中的 ffff::ffff 的整数形式 */
    uint8_t                         suffix[16];     /**< 相当于 ffff::ffff/64 中的 64 的位表示（网络字节序） */
    uint32_t                        suffix_num;     /**< 相当于 ffff::ffff/64 中的 64 */
} ipv6_t;
#endif

#endif // !NGX_HTTP_WAF_MODULE_TYPE_H