/**
 * @file ngx_http_waf_module_ip_hash_table.h
 * @brief IP 频次统计表
*/

#ifndef NGX_HTTP_WAF_MODULE_CHECK_h
#define NGX_HTTP_WAF_MODULE_CHECK_h

#include <uthash.h>
#include <ngx_http_waf_module_macro.h>
#include <ngx_http_waf_module_type.h>

/**
 * @defgroup ip_hash_table IP 频次统计表
 * @addtogroup ip_hash_table IP 频次统计表
 * @brief 统计 IPV4、IPV6 的访问频次。
 * @{
*/


/**
 * @brief 初始化一个 ip 哈希表。
 * @param[out] table 需要初始化的哈希表，调用前置空即可。
 * @param[in] memory_pool 初始化和需后续插入所需的内存池。
 * @param[in] ip_type 存储的 IP 类型。
 * @li @code ip_type == AF_INET @endcode 表示 IPV4。
 * @li @code ip_type == AF_INET6 @endcode 表示 IPV6。
 * @return 返回 SUCCESS 表示成功，反之返回 FAIL。
 * @retval SUCCESS 初始化成功。
 * @retval FAIL 初始化失败。
*/
ngx_int_t ip_hash_table_init(ip_hash_table_t** table, ngx_pool_t* memory_pool, int ip_type);

/**
 * @brief 添加一项
 * @param[in] table 要操作的哈希表
 * @param[in] inx_addr ip 地址结构体，类型只能是 @code struct in_addr @endcode 或 @code struct in6_addr @endcode。
 * @param[in] times 当前 ip 在一分钟内的访问次数。
 * @param[in] start_time 何时开始记录此 ip 的访问次数。
 * @return 返回 SUCCESS 表示成功，反之返回 FAIL。
 * @retval SUCCESS 添加成功。
 * @retval FAIL 添加失败。
*/
ngx_int_t ip_hash_table_add(ip_hash_table_t* table, void* inx_addr, ngx_uint_t times, time_t start_time);

/**
 * @brief 寻找一项
 * @param[in] table 要操作的哈希表
 * @param[in] inx_addr ip 地址结构体，类型只能是 @code struct in_addr @endcode 或 @code struct in6_addr @endcode。
 * @param[out] ip_hash_table_item 找到之后相关的内容会存储到这里。
 * @return 返回 SUCCESS 表示找到，反之返回 FAIL。
 * @retval SUCCESS 找到。
 * @retval FAIL 没找到。
*/
ngx_int_t ip_hash_table_find(ip_hash_table_t* table, void* inx_addr, ip_hash_table_item_t** ip_hash_table_item);

/*
 * @brief 删除一项
 * @param[in] table 要操作的哈希表
 * @param[in] inx_addr ip 地址结构体，类型只能是 @code struct in_addr @endcode 或 @code struct in6_addr @endcode。
 * @return 返回 SUCCESS 表示删除成功，反之返回 FAIL。
 * @retval SUCCESS 删除成功。
 * @retval FAIL 删除失败。
 * @attention 不建议在处理请求的时候使用此函数，因为此函数的时间复杂度为 O(n)。
*/
// ngx_int_t ip_hash_table_delete(ip_hash_table_t* table, void* inx_addr);


/**
 * @}
*/


ngx_int_t ip_hash_table_init(ip_hash_table_t** table, ngx_pool_t* memory_pool, int ip_type) {
    if (memory_pool == NULL) {
        return FAIL;
    }

    *table = (ip_hash_table_t*)ngx_pcalloc(memory_pool, sizeof(ip_hash_table_t));
    if (*table == NULL) {
        return FAIL;
    }

    (*table)->ip_type = ip_type;
    (*table)->memory_pool = memory_pool;
    (*table)->head = NULL;
    (*table)->length = 0;

    return SUCCESS;
}

ngx_int_t ip_hash_table_add(ip_hash_table_t* table, void* inx_addr, ngx_uint_t times, time_t start_time) {
    if (table == NULL || inx_addr == NULL) {
        return FAIL;
    }

    ip_hash_table_item_t* hash_item = NULL;

    if (ip_hash_table_find(table, inx_addr, &hash_item) == SUCCESS) {
        return FAIL;
    }

    hash_item = (ip_hash_table_item_t*)ngx_pcalloc(table->memory_pool, sizeof(ip_hash_table_item_t));
    if (hash_item == NULL) {
            return FAIL;
    }

    if (table->ip_type == AF_INET) {
        memcpy(&(hash_item->key.ipv4), inx_addr, sizeof(struct in_addr));
    } else if (table->ip_type == AF_INET6) {
        memcpy(&(hash_item->key.ipv6), inx_addr, sizeof(struct in6_addr));
    }

    hash_item->times = times;
    hash_item->start_time = start_time;
    if (table->ip_type == AF_INET) {
        HASH_ADD(hh, table->head, key.ipv4, sizeof(hash_item->key.ipv4), hash_item);
    } else if (table->ip_type == AF_INET6) {
        HASH_ADD(hh, table->head, key.ipv6, sizeof(hash_item->key.ipv6), hash_item);
    }

    ++(table->length);
    
    return SUCCESS;
}

ngx_int_t ip_hash_table_find(ip_hash_table_t* table, void* inx_addr, ip_hash_table_item_t** ip_hash_table_item) {
    if (table == NULL || inx_addr == NULL || ip_hash_table_item == NULL) {
        return FAIL;
    }

    *ip_hash_table_item = NULL;
    if (table->ip_type == AF_INET) {
        HASH_FIND(hh, table->head, inx_addr, sizeof(struct in_addr), *ip_hash_table_item);
    } else if (table->ip_type == AF_INET6) {
        HASH_FIND(hh, table->head, inx_addr, sizeof(struct in6_addr), *ip_hash_table_item);
    }

    if (*ip_hash_table_item == NULL) {
        return FAIL;
    }
    return SUCCESS;
}

// ngx_int_t ip_hash_table_delete(ip_hash_table_t* table, void* inx_addr) {
//     if (table == NULL || inx_addr == NULL) {
//         return FAIL;
//     }

//     ip_hash_table_item_t* hash_item = NULL;
//     if (ip_hash_table_find(table, inx_addr, &hash_item) != SUCCESS) {
//         return FAIL;
//     }

//     HASH_DEL(table->head, hash_item);
//     ngx_pfree(table->memory_pool ,hash_item);

//     --(table->length);

//     return SUCCESS;
// }

#endif