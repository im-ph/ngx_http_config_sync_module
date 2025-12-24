/*
 * ngx_http_config_sync_utils.c
 * Nginx Configuration Sync Module - Utility Functions Implementation
 */

#include "ngx_http_config_sync_utils.h"
#include <sys/stat.h>

/* Copy ngx_str_t */
ngx_int_t
ngx_config_sync_str_copy(ngx_pool_t *pool, ngx_str_t *dst, ngx_str_t *src)
{
    dst->data = ngx_pnalloc(pool, src->len + 1);
    if (dst->data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(dst->data, src->data, src->len);
    dst->data[src->len] = '\0';
    dst->len = src->len;

    return NGX_OK;
}

/* Create ngx_str_t from C string */
ngx_int_t
ngx_config_sync_str_from_cstr(ngx_pool_t *pool, ngx_str_t *dst, const char *src)
{
    size_t len = ngx_strlen(src);

    dst->data = ngx_pnalloc(pool, len + 1);
    if (dst->data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(dst->data, src, len);
    dst->data[len] = '\0';
    dst->len = len;

    return NGX_OK;
}

/* Join two paths */
ngx_int_t
ngx_config_sync_path_join(ngx_pool_t *pool, ngx_str_t *result,
    ngx_str_t *base, ngx_str_t *path)
{
    u_char *p;
    size_t  len;

    /* Calculate length */
    len = base->len + 1 + path->len;

    p = ngx_pnalloc(pool, len + 1);
    if (p == NULL) {
        return NGX_ERROR;
    }

    result->data = p;
    result->len = ngx_sprintf(p, "%V/%V", base, path) - p;

    return NGX_OK;
}

/* Check if path exists */
ngx_int_t
ngx_config_sync_path_exists(ngx_str_t *path)
{
    struct stat st;
    u_char      buf[NGX_MAX_PATH];

    if (path->len >= NGX_MAX_PATH) {
        return NGX_ERROR;
    }

    ngx_memcpy(buf, path->data, path->len);
    buf[path->len] = '\0';

    if (stat((char *) buf, &st) == 0) {
        return NGX_OK;
    }

    return NGX_ERROR;
}

/* Create directory recursively */
ngx_int_t
ngx_config_sync_mkdir_p(ngx_str_t *path)
{
    u_char  buf[NGX_MAX_PATH];
    u_char *p;
    size_t  len;

    if (path->len >= NGX_MAX_PATH) {
        return NGX_ERROR;
    }

    ngx_memcpy(buf, path->data, path->len);
    buf[path->len] = '\0';

    len = path->len;

    for (p = buf + 1; p < buf + len; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir((char *) buf, 0755) != 0) {
                if (errno != EEXIST) {
                    return NGX_ERROR;
                }
            }
            *p = '/';
        }
    }

    if (mkdir((char *) buf, 0755) != 0) {
        if (errno != EEXIST) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

/* Format time as ISO 8601 string */
ngx_int_t
ngx_config_sync_format_time(ngx_pool_t *pool, time_t t, ngx_str_t *result)
{
    struct tm  *tm;
    u_char     *p;

    tm = gmtime(&t);
    if (tm == NULL) {
        return NGX_ERROR;
    }

    /* ISO 8601 format: YYYY-MM-DDTHH:MM:SSZ */
    p = ngx_pnalloc(pool, 21);
    if (p == NULL) {
        return NGX_ERROR;
    }

    result->data = p;
    result->len = ngx_sprintf(p, "%04d-%02d-%02dT%02d:%02d:%02dZ",
                              tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
                              tm->tm_hour, tm->tm_min, tm->tm_sec) - p;

    return NGX_OK;
}
