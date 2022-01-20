#include <ngx_http_waf_module_sysguard.h>


typedef struct {
    double      load[3];    /* 1, 5, 15 分钟的平均系统负载 */
    double      ratio_ram;  /* 内存占用率 */
    double      ratio_swap; /* 交换内存占用率 */

    ngx_uint_t  total_ram;  /* 总内存大小（字节） */
    ngx_uint_t  free_ram;   /* 可用内存大小（字节） */
    ngx_uint_t  swap;       /* 交换内存总大小（字节） */
    ngx_uint_t  free_swap;  /* 可用交换内存大小（字节） */
} _sysinfo_t;


static ngx_int_t _get_sysinfo(ngx_http_request_t* r, _sysinfo_t* info);


ngx_int_t ngx_http_waf_handler_sysguard(ngx_http_request_t* r) {
    ngx_http_waf_dp_func_start(r);

    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, NULL);

    if (ngx_http_waf_is_unset_or_disable_value(loc_conf->waf_sysguard)) {
        ngx_http_waf_dp(r, "nothing to do ... return");
        ngx_http_waf_dp_func_end(r);
        return NGX_HTTP_WAF_NOT_MATCHED;
    }

    action_t* action = NULL;

    _sysinfo_t info;

    ngx_http_waf_dp(r, "getting sysinfo");
    if (_get_sysinfo(r, &info) != NGX_HTTP_WAF_SUCCESS) {
        ngx_http_waf_dp(r, "fail ... return");
        ngx_http_waf_append_action_return(r, NGX_HTTP_INTERNAL_SERVER_ERROR, ACTION_FLAG_FROM_SYSGUARD);
        return NGX_HTTP_WAF_MATCHED;
    }

    ngx_http_waf_dpf(r, "load_threshold: %.2f", loc_conf->waf_sysguard_load_threshold);
    ngx_http_waf_dpf(r, "mem_threshold: %.2f", loc_conf->waf_sysguard_mem_threshold);
    ngx_http_waf_dpf(r, "swap_threshold: %.2f", loc_conf->waf_sysguard_swap_threshold);

    ngx_http_waf_dpf(r, "load: %.2f, %.2f, %.2f", info.load[0], info.load[1], info.load[2]);
    ngx_http_waf_dpf(r, "mem: %.2f", info.ratio_ram);
    ngx_http_waf_dpf(r, "swap: %.2f", info.ratio_swap);

    if (info.load[0] - loc_conf->waf_sysguard_load_threshold > 1e-7) {
        ngx_http_waf_set_rule_info(r, "SYSGUARD", "LOAD", NGX_HTTP_WAF_TRUE, NGX_HTTP_WAF_TRUE);
        ngx_http_waf_copy_action_chain(r->pool, action, loc_conf->action_chain_sysguard_load);
        ngx_http_waf_append_action_chain(r, action);
        ngx_http_waf_dp_func_end(r);
        return NGX_HTTP_WAF_MATCHED;
    }

    if (info.ratio_ram - loc_conf->waf_sysguard_mem_threshold >= 1e-7) {
        ngx_http_waf_set_rule_info(r, "SYSGUARD", "MEM", NGX_HTTP_WAF_TRUE, NGX_HTTP_WAF_TRUE);
        ngx_http_waf_copy_action_chain(r->pool, action, loc_conf->action_chain_sysguard_mem);
        ngx_http_waf_append_action_chain(r, action);
        ngx_http_waf_dp_func_end(r);
        return NGX_HTTP_WAF_MATCHED;
    }

    if (info.ratio_swap - loc_conf->waf_sysguard_swap_threshold >= 1e-7) {
        ngx_http_waf_set_rule_info(r, "SYSGUARD", "SWAP", NGX_HTTP_WAF_TRUE, NGX_HTTP_WAF_TRUE);
        ngx_http_waf_copy_action_chain(r->pool, action, loc_conf->action_chain_sysguard_swap);
        ngx_http_waf_append_action_chain(r, action);
        ngx_http_waf_dp_func_end(r);
        return NGX_HTTP_WAF_MATCHED;
    }

    ngx_http_waf_dp_func_end(r);
    return NGX_HTTP_WAF_NOT_MATCHED;
}


static ngx_int_t _get_sysinfo(ngx_http_request_t* r, _sysinfo_t* info) {
    static time_t s_last_get_time = 0;
    static _sysinfo_t s_info;

    ngx_http_waf_dp_func_start(r);

    ngx_http_waf_loc_conf_t* loc_conf = NULL;
    ngx_http_waf_get_ctx_and_conf(r, &loc_conf, NULL);

    if (difftime(time(NULL), s_last_get_time) > loc_conf->waf_sysguard_interval) {
        s_last_get_time = time(NULL);

        struct sysinfo _info;

        if (sysinfo(&_info)) {
            return NGX_HTTP_WAF_FAIL;
        }

        info->load[0] = (double)(_info.loads[0]) / (double)(1 << SI_LOAD_SHIFT);
        info->load[1] = (double)(_info.loads[1]) / (double)(1 << SI_LOAD_SHIFT);
        info->load[2] = (double)(_info.loads[2]) / (double)(1 << SI_LOAD_SHIFT);

        info->ratio_ram = (double)(_info.totalram - _info.freeram) / (double)_info.totalram;
        info->ratio_swap = (double)(_info.totalswap - _info.freeswap) / (double)_info.totalswap;

        info->total_ram = _info.totalram;
        info->free_ram = _info.freeram;
        info->swap = _info.totalswap;
        info->free_swap = _info.freeswap;

        ngx_memcpy(&s_info, info, sizeof(_sysinfo_t));

    } else {
        ngx_memcpy(info, &s_info, sizeof(_sysinfo_t));
    }

    ngx_http_waf_dp_func_end(r);
    return NGX_HTTP_WAF_SUCCESS;
}