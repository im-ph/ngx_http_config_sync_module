/*
 * ngx_http_config_sync_handler.h
 * Nginx Configuration Sync Module - HTTP Handler Header
 */

#ifndef _NGX_HTTP_CONFIG_SYNC_HANDLER_H_
#define _NGX_HTTP_CONFIG_SYNC_HANDLER_H_

#include "ngx_http_config_sync_module.h"

/* Main HTTP handler */
ngx_int_t ngx_http_config_sync_handler(ngx_http_request_t *r);

/* API endpoint handlers */
ngx_int_t ngx_http_config_sync_get_config(ngx_http_request_t *r);
ngx_int_t ngx_http_config_sync_post_config(ngx_http_request_t *r);
ngx_int_t ngx_http_config_sync_push_handler(ngx_http_request_t *r);
ngx_int_t ngx_http_config_sync_pull_handler(ngx_http_request_t *r);
ngx_int_t ngx_http_config_sync_status_handler(ngx_http_request_t *r);
ngx_int_t ngx_http_config_sync_versions_handler(ngx_http_request_t *r);
ngx_int_t ngx_http_config_sync_rollback_handler(ngx_http_request_t *r);
ngx_int_t ngx_http_config_sync_sites_handler(ngx_http_request_t *r);
ngx_int_t ngx_http_config_sync_enable_site_handler(ngx_http_request_t *r);
ngx_int_t ngx_http_config_sync_disable_site_handler(ngx_http_request_t *r);

/* Response helpers */
ngx_int_t ngx_http_config_sync_send_json_response(ngx_http_request_t *r,
    ngx_uint_t status, ngx_str_t *json);
ngx_int_t ngx_http_config_sync_send_error(ngx_http_request_t *r,
    ngx_uint_t status, const char *code, const char *message);
ngx_int_t ngx_http_config_sync_send_success(ngx_http_request_t *r,
    ngx_str_t *data);

#endif /* _NGX_HTTP_CONFIG_SYNC_HANDLER_H_ */
