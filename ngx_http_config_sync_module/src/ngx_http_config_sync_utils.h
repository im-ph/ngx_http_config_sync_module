/*
 * ngx_http_config_sync_utils.h
 * Nginx Configuration Sync Module - Utility Functions Header
 */

#ifndef _NGX_HTTP_CONFIG_SYNC_UTILS_H_
#define _NGX_HTTP_CONFIG_SYNC_UTILS_H_

#include "ngx_http_config_sync_module.h"

/* String utilities */
ngx_int_t ngx_config_sync_str_copy(ngx_pool_t *pool, ngx_str_t *dst,
    ngx_str_t *src);
ngx_int_t ngx_config_sync_str_from_cstr(ngx_pool_t *pool, ngx_str_t *dst,
    const char *src);

/* Path utilities */
ngx_int_t ngx_config_sync_path_join(ngx_pool_t *pool, ngx_str_t *result,
    ngx_str_t *base, ngx_str_t *path);
ngx_int_t ngx_config_sync_path_exists(ngx_str_t *path);
ngx_int_t ngx_config_sync_mkdir_p(ngx_str_t *path);

/* Time utilities */
ngx_int_t ngx_config_sync_format_time(ngx_pool_t *pool, time_t t,
    ngx_str_t *result);

#endif /* _NGX_HTTP_CONFIG_SYNC_UTILS_H_ */
