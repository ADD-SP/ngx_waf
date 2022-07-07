/**
 * @file ngx_http_waf_module_ip_trie.h
 * @brief IP 前缀树。
*/

#include <ngx_http_waf_module_macro.h>
#include <ngx_http_waf_module_type.h>
#include <ngx_http_waf_module_mem_pool.h>

#ifndef NGX_HTTP_WAF_MODULE_IP_TRIE_h
#define NGX_HTTP_WAF_MODULE_IP_TRIE_h

/**
 * @defgroup ip_trie IP 前缀树
 * @addtogroup ip_trie IP 前缀树
 * @{
*/

/**
 * @brief 初始化一个前缀树。
 * @param[out] trie 要初始化的前缀树。
 * @param[in] memory_pool 初始化、添加、删除节点所用的内存池。
 * @param[in] ip_type 存储的 IP 地址类型。
 * @return 返回 NGX_HTTP_WAF_SUCCESS 表示初始化成功，反之为 NGX_HTTP_WAF_FAIL。
*/
ngx_int_t ip_trie_init(ip_trie_t* trie, mem_pool_type_e pool_type, void* native_pool, int ip_type);


/**
 * @brief 插入一个 IP 地址。
 * @param[in] trie 要操作的前缀树。
 * @param[in] inx_addr IP 地址。
 * @param[in] suffix_num IP 网段长度。
 * @param[in] text IP 的字符串形式。
 * @return 返回 NGX_HTTP_WAF_SUCCESS 表示成功，反之为 NGX_HTTP_WAF_FAIL。
*/
ngx_int_t ip_trie_add(ip_trie_t* trie, inx_addr_t* inx_addr, uint32_t suffix_num, void* data, size_t data_byte_length);

/**
 * @brief 查找 IP 是否存在。
 * @param[in] trie 要操作的前缀树。
 * @param[in] inx_addr IP 地址。
 * @param[out] ip_trie_node 找到之后此指针将指向对应的节点。
 * @return 返回 NGX_HTTP_WAF_SUCCESS 表示找到，反之为 FAIL。
*/
ngx_int_t ip_trie_find(ip_trie_t* trie, inx_addr_t* inx_addr, ip_trie_node_t** ip_trie_node);

/**
 * @brief 删除一个 IP 地址。
 * @param[in] trie 要操作的前缀树。
 * @param[in] inx_addr IP 地址。
 * @return 成功返回 NGX_HTTP_WAF_SUCCESS，反之则不是
 * @warning 不会释放节点所在占用的内存，但是会释放节点的 data 域所指向的内存。
*/
// static ngx_int_t ip_trie_delete(ip_trie_t* trie, inx_addr_t* inx_addr);

/**
 * @brief 清空整个树，除根节点以外的全部节点的内存和 data 域指向的内存。
 * @param[in] trie 要操作的前缀树。
 * @return 成功返回 NGX_HTTP_WAF_SUCCESS，反之则不是
*/
// static ngx_int_t ip_trie_clear(ip_trie_t* trie);


/**
 * @brief 先序遍历，并将每个节点存入 head 为头的链表里。
 * @param[in] node 开始遍历的节点
 * @param[out] head 链表头
*/
// static void _ip_trie_traversal(ip_trie_node_t* node, circular_doublly_linked_list_t** head);

/**
 * @}
*/

#endif
