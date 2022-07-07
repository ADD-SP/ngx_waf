/**
 * @file ngx_http_waf_module_type.h
 * @brief 相关结构体的定义
*/

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
// #include <ngx_regex.h>
// #include <ngx_inet.h>
#include <ngx_http_waf_module_macro.h>
#include <uthash.h>
#include <utarray.h>
#include <utlist.h>


#ifndef NGX_HTTP_WAF_MODULE_TYPE_H
#define NGX_HTTP_WAF_MODULE_TYPE_H

/**
 * @typedef ngx_http_waf_check
 * @brief 请求检查函数的函数指针
 * @param[out] out_http_status 当触发规则时需要返回的 HTTP 状态码。
*/
typedef ngx_int_t (*ngx_http_waf_check_pt)(ngx_http_request_t* r, ngx_int_t* out_http_status);


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
 * @enum memory_pool_type_e
 * @brief 内存池类型
*/
typedef enum {
    std,            /**< malloc */
    gernal_pool,    /**< ngx_pool_t */
    slab_pool       /**< ngx_slab_pool_t */
} mem_pool_type_e;


/**
 * @enum vm_code_type_e
 * @brief 虚拟机指令类型
*/
typedef enum {
    VM_CODE_NOP,                /**< 空指令，什么都不做，继续执行下一条指令。 */
    VM_CODE_PUSH_INT,           /**< 将一个整数压入栈中。 */
    VM_CODE_PUSH_STR,           /**< 将一个字符串压入栈中。 */
    VM_CODE_PUSH_CLIENT_IP,     /**< 将客户端 IP（struct in_addr 或 struct_in6addr）压入栈中。 */
    VM_CODE_PUSH_URL,           /**< 将 URL 压入栈中。 */
    VM_CODE_PUSH_QUERY_STRING,  /**< 将查询字符串的 key 对应的 value 压入栈中。 */
    VM_CODE_PUSH_REFERER,       /**< 将 referer 压入栈中。 */
    VM_CODE_PUSH_USER_AGENT,    /**< 将 user-agent 压入栈中。 */
    VM_CODE_PUSH_HEADER_IN,     /**< 将请求头中的 key 对应的 value 压入栈中。 */
    VM_CODE_PUSH_COOKIE,        /**< 将 cookie 中的 key 对应的 value 压入栈中。 */
    // VM_CODE_POP,                /**<  */
    // VM_CODE_TOP,                /**<  */
    VM_CODE_OP_NOT,             /**< 将栈顶的布尔值反转 */
    VM_CODE_OP_AND,             /**< 弹出两个布尔值，逻辑与后压入栈中。 */
    VM_CODE_OP_OR,              /**< 弹出两个布尔值，逻辑或后压入栈中 */
    VM_CODE_OP_CONTAINS,        /**< 弹出两个字符串，判断第一个弹出的字符串是否是第二个弹出的字符串的子串，并将结果压入栈中 */
    VM_CODE_OP_MATCHES,         /**< 弹出两个字符串，将第一个字符串编译为正则表达式对第二个字符串进行正则匹配，并将结果压入栈中。 */
    VM_CODE_OP_EQUALS,          /**< 弹出两个字符串判断两个字符串是否相等，并将结果压入栈中。 */
    VM_CODE_OP_BELONG_TO,       /**< 依次弹出一个 IP 块和一个 IP，判断 IP 是否包含在 IP 块中，并将结果压入栈中。 */
    VM_CODE_OP_SQLI_DETN,       /**< 弹出一个字符串检测其中是否存在 SQL 注入，并将结果压入栈中。 */
    VM_CODE_OP_XSS_DETN,        /**< 弹出一个字符串检测其中是否存在 XSS 攻击，并将结果压入栈中。 */
    VM_CODE_ACT_RETURN,         /**< 如果栈顶的布尔值为真则返回指定的 http 状态码。 */
    VM_CODE_ACT_ALLOW           /**< 如果栈顶的布尔值为真则放行本次请求。 */
} vm_code_type_e;


/**
 * @enum vm_data_type_e
 * @brief 虚拟机数据类型
*/
typedef enum {
    VM_DATA_VOID,               /**< 无类型数据，应该被忽略。 */
    VM_DATA_STR,                /**< 字符串类型 */
    VM_DATA_INT,                /**< 整数类型 */
    VM_DATA_BOOL,               /**< 布尔类型 */
    VM_DATA_IPV4,               /**< IPV4 */
#if (NGX_HAVE_INET6)
    VM_DATA_IPV6                /**< IPV6 */
#endif
} vm_data_type_e;


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
 * @struct mem_pool_t
 * @brief 包含常规内存池或 slab 内存池
*/
typedef struct memo_pool_s {
    mem_pool_type_e                     type;                   /**< 标识内存池的类型 */
    size_t                              used_mem;               /**< 正在使用的内存大小（字节） */
    union {
        ngx_pool_t         *gernal_pool;                        /**< 常规内存池 */
        ngx_slab_pool_t    *slab_pool;                          /**< slab 内存池 */
    } native_pool;                                              /**< 内存池 */
} mem_pool_t;


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
    mem_pool_t                        pool;               /**< 内存池 */
    size_t                            capacity;           /**< 最多嫩容纳多少个缓存项 */
    lru_cache_item_t                 *hash_head;          /**< uthash 的表头 */
    lru_cache_item_t                 *chain_head;         /**< utlist 的表头 */
} lru_cache_t;


/**
 * @struct token_bucket_t
 * @brief 令牌桶
*/
typedef struct token_bucket_s{
    inx_addr_t      inx_addr;           /**< 作为哈希表中的 key */
    ngx_uint_t      count;              /**< 令牌剩余量 */
    ngx_int_t       is_ban;             /**< 令牌桶是否暂时被禁止 */
    time_t          last_ban_time;      /**< 最后一次开始禁止令牌桶的时间 */
    UT_hash_handle  hh;                 /**< uthash 关键成员 */
} token_bucket_t;


/**
 * @struct token_bucket_set_t
 * @brief 令牌桶集合
*/
typedef struct token_bucket_set_s{
    mem_pool_t      pool;               /**< 使用的内存池 */
    ngx_uint_t      ban_duration;       /**< 当令牌桶为空时自动禁止该桶一段时间（分钟）*/
    time_t          last_put;           /**< 上次集中添加令牌的时间 */
    time_t          last_clear;         /**< 上次清空令牌桶的时间 */
    ngx_uint_t      init_count;         /**< 令牌桶内初始的令牌数量 */
    ngx_uint_t      bucket_count;       /**< 已经有多少个令牌桶 */
    token_bucket_t *head;               /**< 哈希表标头 */
} token_bucket_set_t;


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
    mem_pool_t          pool;           /**< 使用的内存池 */
} ip_trie_t;


/**
 * @struct ngx_http_waf_ctx_t
 * @brief 每个请求的上下文
*/
typedef struct ngx_http_waf_ctx_s {
    ngx_int_t                       checked;                                    /**< 是否启动了检测流程 */
    ngx_int_t                       blocked;                                    /**< 是否拦截了本次请求 */
    double                          spend;                                      /**< 本次检查花费的时间（毫秒） */
    u_char                          rule_type[128];                             /**< 触发的规则类型 */
    u_char                          rule_deatils[NGX_HTTP_WAF_RULE_MAX_LEN];    /**< 触发的规则内容 */
    ngx_int_t                       read_body_done;
    ngx_int_t                       waiting_more_body;                          /**< 是否等待读取更多请求体 */
    ngx_int_t                       has_req_body;                               /**< 字段 req_body 是否以己经存储了请求体 */
    ngx_buf_t                       req_body;                                   /**< 请求体 */
} ngx_http_waf_ctx_t;


/**
 * @struct ngx_http_waf_loc_conf_t
*/
typedef struct ngx_http_waf_main_conf_s {
    ngx_array_t                    *local_caches;                               /**< 已经启用的所有的缓存管理器数组 */
} ngx_http_waf_main_conf_t;


/**
 * @struct ngx_http_waf_loc_conf_t
 * @brief 每个 server 块的配置块
*/
typedef struct ngx_http_waf_loc_conf_s {
    struct ngx_http_waf_loc_conf_s *parent;                                     /**< 上层配置，用来定位 CC 防护所使用的共享内存 */
    u_char                          random_str[129];                            /**< 随机字符串 */
    ngx_str_t                       waf_under_attack_uri;                       /**< 五秒盾的 URI */
    ngx_int_t                       waf_under_attack;                           /**< 是否启用五秒盾 */
    ngx_int_t                       is_alloc;                                   /**< 是否已经分配的存储规则的容器的内存 */
    ngx_int_t                       waf;                                        /**< 是否启用本模块 */
    ngx_str_t                       waf_rule_path;                              /**< 配置文件所在目录 */  
    uint_fast64_t                   waf_mode;                                   /**< 检测模式 */
    ngx_int_t                       waf_cc_deny_limit;                          /**< CC 防御的限制频率 */
    ngx_int_t                       waf_cc_deny_duration;                       /**< CC 防御的拉黑时长（秒） */
    ngx_int_t                       waf_cc_deny_shm_zone_size;                  /**< CC 防御所使用的共享内存的大小（字节） */
    ngx_int_t                       waf_inspection_capacity;                    /**< 用于缓存检查结果的共享内存的大小（字节） */
    ngx_int_t                       waf_http_status;                            /**< 常规检测项目拦截后返回的状态码 */
    ngx_int_t                       waf_http_status_cc;                         /**< CC 防护出发后返回的状态码 */
    ip_trie_t                      *black_ipv4;                                 /**< IPV4 黑名单 */
#if (NGX_HAVE_INET6)
    ip_trie_t                      *black_ipv6;                                 /**< IPV6 黑名单 */
#endif
    ngx_array_t                    *black_url;                                  /**< URL 黑名单 */
    ngx_array_t                    *black_args;                                 /**< args 黑名单 */
    ngx_array_t                    *black_ua;                                   /**< user-agent 黑名单 */
    ngx_array_t                    *black_referer;                              /**< Referer 黑名单 */
    ngx_array_t                    *black_cookie;                               /**< Cookie 黑名单 */
    ngx_array_t                    *black_post;                                 /**< 请求体内容黑名单 */
    ip_trie_t                      *white_ipv4;                                 /**< IPV4 白名单 */
#if (NGX_HAVE_INET6)
    ip_trie_t                      *white_ipv6;                                 /**< IPV6 白名单 */
#endif
    ngx_array_t                    *white_url;                                  /**< URL 白名单 */
    ngx_array_t                    *white_referer;                              /**< Referer 白名单 */
    UT_array                       *advanced_rule;                              /**< 高级规则表 */
    ngx_shm_zone_t                 *shm_zone_cc_deny;                           /**< 共享内存 */
    lru_cache_t                    *ip_access_statistics;                       /**< IP 访问频率统计表 */
    lru_cache_t                    *black_url_inspection_cache;                 /**< URL 黑名单检查缓存 */
    lru_cache_t                    *black_args_inspection_cache;                /**< ARGS 黑名单检查缓存 */
    lru_cache_t                    *black_ua_inspection_cache;                  /**< User-Agent 黑名单检查缓存 */
    lru_cache_t                    *black_referer_inspection_cache;             /**< Referer 黑名单检查缓存 */
    lru_cache_t                    *black_cookie_inspection_cache;              /**< Cookie 黑名单检查缓存 */
    lru_cache_t                    *white_url_inspection_cache;                 /**< URL 白名单检查缓存 */
    lru_cache_t                    *white_referer_inspection_cache;             /**< Referer 白名单检查缓存 */
    ngx_int_t                       is_custom_priority;                         /**< 用户是否自定义了优先级 */
    ngx_http_waf_check_pt           check_proc[20];                             /**< 各种检测流程的启动函数 */
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



/**
 * @struct vm_stack_arg_s
 * @brief 虚拟机指令参数
*/
typedef struct vm_stack_arg_s {
    vm_data_type_e                          type[4];            /**< 每个参数的类型 */
    size_t                                  argc;               /**< 参数的数量 */
    union {
        int         int_val;
        ngx_str_t   str_val;
        uint8_t     bool_val;
        ipv4_t      ipv4_val;
#if (NGX_HAVE_INET6)
        ipv6_t      ipv6_val;
#endif
        inx_addr_t  inx_addr_val;
    }                                       value[4];           /**< 每个参数的值 */
    struct vm_stack_arg_s                  *utstack_handle;     /**< utstack 关键成员 */
} vm_stack_arg_t;



/**
 * @struct vm_code_t
 * @brief 虚拟机指令
*/
typedef struct vm_code_s {
    vm_code_type_e          type;   /**< 指令类型 */
    struct vm_stack_arg_s   argv;   /**< 指令参数 */
} vm_code_t;

#endif // !NGX_HTTP_WAF_MODULE_TYPE_H