/*
 * ngx_http_config_sync_auth.h
 * Nginx Configuration Sync Module - Authentication Header
 */

#ifndef _NGX_HTTP_CONFIG_SYNC_AUTH_H_
#define _NGX_HTTP_CONFIG_SYNC_AUTH_H_

#include "ngx_http_config_sync_module.h"

/* Check request authentication */
ngx_int_t ngx_http_config_sync_check_auth(ngx_http_request_t *r,
    ngx_http_config_sync_loc_conf_t *conf);

/* Get auth token from request header */
ngx_int_t ngx_http_config_sync_get_auth_token(ngx_http_request_t *r,
    ngx_str_t *token);

#endif /* _NGX_HTTP_CONFIG_SYNC_AUTH_H_ */
