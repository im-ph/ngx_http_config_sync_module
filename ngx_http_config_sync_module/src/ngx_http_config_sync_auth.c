/*
 * ngx_http_config_sync_auth.c
 * Nginx Configuration Sync Module - Authentication Implementation
 */

#include "ngx_http_config_sync_auth.h"

/* Authorization header prefix */
static ngx_str_t bearer_prefix = ngx_string("Bearer ");

/* Get auth token from Authorization header */
ngx_int_t
ngx_http_config_sync_get_auth_token(ngx_http_request_t *r, ngx_str_t *token)
{
    ngx_table_elt_t *auth_header;

    /* Find Authorization header */
    auth_header = r->headers_in.authorization;
    if (auth_header == NULL) {
        token->len = 0;
        token->data = NULL;
        return NGX_DECLINED;
    }

    /* Check for Bearer prefix */
    if (auth_header->value.len <= bearer_prefix.len ||
        ngx_strncasecmp(auth_header->value.data, bearer_prefix.data, 
                        bearer_prefix.len) != 0) {
        token->len = 0;
        token->data = NULL;
        return NGX_DECLINED;
    }

    /* Extract token */
    token->data = auth_header->value.data + bearer_prefix.len;
    token->len = auth_header->value.len - bearer_prefix.len;

    return NGX_OK;
}

/* Check request authentication */
ngx_int_t
ngx_http_config_sync_check_auth(ngx_http_request_t *r,
    ngx_http_config_sync_loc_conf_t *conf)
{
    ngx_str_t token;

    /* If no auth token configured, allow all requests */
    if (conf->auth_token.len == 0) {
        return NGX_OK;
    }

    /* Get token from request */
    if (ngx_http_config_sync_get_auth_token(r, &token) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "config_sync: missing authorization header from %V",
                      &r->connection->addr_text);
        return NGX_ERROR;
    }

    /* Compare tokens */
    if (token.len != conf->auth_token.len ||
        ngx_strncmp(token.data, conf->auth_token.data, token.len) != 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "config_sync: invalid auth token from %V",
                      &r->connection->addr_text);
        return NGX_ERROR;
    }

    return NGX_OK;
}
