/**
 * @file ngx_http_waf_module_type.h
 * @brief 相关结构体的定义
*/

#include <uthash.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_regex.h>
#include <ngx_inet.h>
#include <ngx_http_waf_module_macro.h>


#ifndef NGX_HTTP_WAF_MODULE_TYPE_H
#define NGX_HTTP_WAF_MODULE_TYPE_H

/**
 * @struct inx_addr_t
 * @brief 代表 ipv4 或 ipv6 地址。
*/
typedef union {
    struct in_addr ipv4;
    struct in6_addr ipv6;
} inx_addr_t;

/**
 * @enum memory_pool_type_e
 * @brief 内存池类型
*/
typedef enum {
    gernal_pool, /**< ngx_pool_t */
    slab_pool /**< ngx_slab_pool_t */
} memory_pool_type_e;


/**
 * @struct token_bucket_t
 * @brief 令牌桶
*/
typedef struct {
    inx_addr_t inx_addr; /**< 作为哈希表中的 key */
    ngx_uint_t count; /**< 令牌剩余量 */
    UT_hash_handle hh; /**< uthash 关键成员 */
} token_bucket_t;


/**
 * @struct token_bucket_set_t
 * @brief 令牌桶集合
*/
typedef struct {
    memory_pool_type_e memory_pool_type; /**< 内存池类型 */
    void* memory_pool; /**< 创建令牌桶和释放令牌桶所用的内存池 */
    time_t prev_put; /**< 上次集中添加令牌的时间 */
    time_t prev_clear; /**< 上次清空令牌桶的时间 */
    ngx_uint_t bucket_count; /**< 已经有多少个令牌桶 */
    token_bucket_t *head; /**< 哈希表标头 */
} token_bucket_set_t;


/**
 * @struct ip_trie_node_t
 * @brief 前缀树节点。
*/
typedef struct _ip_trie_node_t{
    int is_ip; /**< 如果为 TRUE 则代表此节点也代表一个 IP，反之则为 FALSE */
    struct _ip_trie_node_t* left; /**< 左子树代表当前位为零 */
    struct _ip_trie_node_t* right; /**< 右子树代表当前位为一 */
    u_char text[64]; /**< ip 地址的字符串形式，用于输入日志。 */
} ip_trie_node_t;

/**
 * @struct ip_trie_t
 * @brief 前缀树。
*/
typedef struct {
    int ip_type; /**< 存储的 IP 地址的类型。 */
    ip_trie_node_t* root; /**< 前缀树树根。 */
    size_t size; /**< 已经存储的 IP 数量。 */
    ngx_pool_t *memory_pool; /**< 用于初始化、添加和删除节点的内存池 */
} ip_trie_t;


/**
 * @struct ngx_http_waf_ctx_t
 * @brief 每个请求的上下文
*/
typedef struct {
    ngx_int_t                       blocked;                    /**< 是否拦截了本次请求 */
    ngx_int_t                       checked_in_pre_access;      /**< 是否在 NGX_HTTP_PREACCESS_PHASE 阶段检查过请求 */
    ngx_int_t                       checked_in_server_rewrite;  /**< 是否在 NGX_HTTP_SERVER_REWRITE_PHASE 阶段检查过请求 */
    u_char                          rule_type[128];             /**< 触发的规则类型 */
    u_char                          rule_deatils[RULE_MAX_LEN]; /**< 触发的规则内容 */
    ngx_int_t                       read_body_done;             /**< 是否已经读取完请求体 */
} ngx_http_waf_ctx_t;

/**
 * @struct ngx_http_waf_srv_conf_t
 * @brief 每个 server 块的配置块
*/
typedef struct {
    ngx_log_t                      *ngx_log;                        /**< 记录内存池在进行操作时的错误日志 */
    ngx_pool_t                     *ngx_pool;                       /**< 模块所使用的内存池 */
    ngx_uint_t                      alloc_times;                    /**< 当前已经从内存池中申请过多少次内存 */
    ngx_int_t                       waf;                            /**< 是否启用本模块 */
    ngx_str_t                       waf_rule_path;                  /**< 配置文件所在目录 */
    ngx_int_t                       waf_mult_mount;                 /**< 是否执行多阶段检查 */
    ngx_uint_t                      waf_mode;                       /**< 检测模式 */
    ngx_int_t                       waf_cc_deny_limit;              /**< CC 防御的限制频率 */
    ngx_int_t                       waf_cc_deny_duration;           /**< CC 防御的拉黑时长（分钟） */
    ip_trie_t                      *black_ipv4;                     /**< IPV4 黑名单 */
    ip_trie_t                      *black_ipv6;                     /**< IPV6 黑名单 */
    ngx_array_t                    *black_url;                      /**< URL 黑名单 */
    ngx_array_t                    *black_args;                     /**< args 黑名单 */
    ngx_array_t                    *black_ua;                       /**< user-agent 黑名单 */
    ngx_array_t                    *black_referer;                  /**< Referer 黑名单 */
    ngx_array_t                    *black_cookie;                   /**< Cookie 黑名单 */
    ngx_array_t                    *black_post;                     /**< 请求体内容黑名单 */
    ip_trie_t                      *white_ipv4;                     /**< IPV4 白名单 */
    ip_trie_t                      *white_ipv6;                     /**< IPV6 白名单 */
    ngx_array_t                    *white_url;                      /**< URL 白名单 */
    ngx_array_t                    *white_referer;                  /**< Referer 白名单 */
    ngx_shm_zone_t                 *shm_zone;                       /**< 共享内存 */
    token_bucket_set_t             *ip_token_bucket_set;            /**< IP 访问令牌桶集合 */
}ngx_http_waf_srv_conf_t;

/**
 * @struct ipv4_t
 * @brief 格式化后的 IPV4
 * @note 注意，无论是 prefix 还是 suffix 都是网络字节序，即大端字节序。
*/
typedef struct {
    u_char                          text[32];       /**< 点分十进制表示法 */
    uint32_t                        prefix;         /**< 相当于 192.168.1.0/24 中的 192.168.1.0 的整数形式 */
    uint32_t                        suffix;         /**< 相当于 192.168.1.0/24 中的 24 */
    uint32_t                        suffix_num;
} ipv4_t;


/**
 * @struct ipv6_t
 * @brief 格式化后的 IPV6
 * @note 注意，无论是 prefix[16] 还是 suffix[16]，他们中的每一项都是网络字节序。
 * 数组的下标同理，下标零代表最高位，下标十五代表最低位。
*/
typedef struct {
    u_char                          text[64];       /**< 冒号十六进制表示法 */
    uint8_t                         prefix[16];     /**< 相当于 ffff::ffff/64 中的 ffff::ffff 的整数形式 */
    uint8_t                         suffix[16];     /**< 相当于 ffff::ffff/64 中的 64 */
    uint32_t                        suffix_num;
} ipv6_t;

#endif // !NGX_HTTP_WAF_MODULE_TYPE_H