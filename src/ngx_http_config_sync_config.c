/*
 * ngx_http_config_sync_config.c
 * Nginx Configuration Sync Module - Config Manager Implementation
 */

#include "ngx_http_config_sync_config.h"
#include "ngx_http_config_sync_utils.h"
#include <openssl/sha.h>
#include <dirent.h>
#include <sys/stat.h>
#include <string.h>

/* Read single file from disk */
ngx_int_t
ngx_config_sync_read_file(ngx_pool_t *pool, ngx_str_t *path,
    ngx_config_file_t *file)
{
    ngx_file_t       ngx_file;
    ngx_file_info_t  fi;
    ssize_t          n;
    u_char          *buf;

    ngx_memzero(&ngx_file, sizeof(ngx_file_t));
    ngx_file.name = *path;
    ngx_file.log = ngx_cycle->log;

    ngx_file.fd = ngx_open_file(path->data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (ngx_file.fd == NGX_INVALID_FILE) {
        return NGX_ERROR;
    }

    if (ngx_fd_info(ngx_file.fd, &fi) == NGX_FILE_ERROR) {
        ngx_close_file(ngx_file.fd);
        return NGX_ERROR;
    }

    file->path = *path;
    file->mtime = ngx_file_mtime(&fi);

    buf = ngx_pnalloc(pool, ngx_file_size(&fi) + 1);
    if (buf == NULL) {
        ngx_close_file(ngx_file.fd);
        return NGX_ERROR;
    }

    n = ngx_read_file(&ngx_file, buf, ngx_file_size(&fi), 0);
    ngx_close_file(ngx_file.fd);

    if (n == NGX_ERROR) {
        return NGX_ERROR;
    }

    buf[n] = '\0';
    file->content.data = buf;
    file->content.len = n;

    /* Calculate hash */
    if (ngx_config_sync_hash_content(pool, &file->content, &file->hash) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* Write single file to disk */
ngx_int_t
ngx_config_sync_write_file(ngx_pool_t *pool, ngx_str_t *path,
    ngx_str_t *content)
{
    ngx_file_t  ngx_file;
    ssize_t     n;

    ngx_memzero(&ngx_file, sizeof(ngx_file_t));
    ngx_file.name = *path;
    ngx_file.log = ngx_cycle->log;

    ngx_file.fd = ngx_open_file(path->data, NGX_FILE_WRONLY,
                                NGX_FILE_CREATE_OR_OPEN|NGX_FILE_TRUNCATE,
                                NGX_FILE_DEFAULT_ACCESS);
    if (ngx_file.fd == NGX_INVALID_FILE) {
        return NGX_ERROR;
    }

    n = ngx_write_file(&ngx_file, content->data, content->len, 0);
    ngx_close_file(ngx_file.fd);

    if (n == NGX_ERROR || (size_t) n != content->len) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* Calculate SHA-256 hash of content */
ngx_int_t
ngx_config_sync_hash_content(ngx_pool_t *pool, ngx_str_t *content,
    ngx_str_t *hash)
{
    unsigned char    md[SHA256_DIGEST_LENGTH];
    u_char          *hex;
    ngx_uint_t       i;

    SHA256(content->data, content->len, md);

    /* Convert to hex string */
    hex = ngx_pnalloc(pool, SHA256_DIGEST_LENGTH * 2 + 1);
    if (hex == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ngx_sprintf(hex + i * 2, "%02x", md[i]);
    }
    hex[SHA256_DIGEST_LENGTH * 2] = '\0';

    hash->data = hex;
    hash->len = SHA256_DIGEST_LENGTH * 2;

    return NGX_OK;
}

/* List files in directory */
ngx_int_t
ngx_config_sync_list_dir(ngx_pool_t *pool, ngx_str_t *dir_path,
    ngx_array_t *files)
{
    DIR            *dir;
    struct dirent  *entry;
    ngx_str_t      *file;
    u_char         *path;
    size_t          len;

    path = ngx_pnalloc(pool, dir_path->len + 1);
    if (path == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(path, dir_path->data, dir_path->len);
    path[dir_path->len] = '\0';

    dir = opendir((char *) path);
    if (dir == NULL) {
        return NGX_ERROR;
    }

    while ((entry = readdir(dir)) != NULL) {
        /* Skip . and .. */
        if (entry->d_name[0] == '.') {
            continue;
        }

        /* Skip directories */
        if (entry->d_type == DT_DIR) {
            continue;
        }

        file = ngx_array_push(files);
        if (file == NULL) {
            closedir(dir);
            return NGX_ERROR;
        }

        len = ngx_strlen(entry->d_name);
        file->data = ngx_pnalloc(pool, len + 1);
        if (file->data == NULL) {
            closedir(dir);
            return NGX_ERROR;
        }

        ngx_memcpy(file->data, entry->d_name, len);
        file->data[len] = '\0';
        file->len = len;
    }

    closedir(dir);
    return NGX_OK;
}

/* Get enabled sites from sites-enabled directory */
ngx_int_t
ngx_config_sync_get_enabled_sites(ngx_pool_t *pool,
    ngx_str_t *sites_enabled_path, ngx_array_t *enabled_sites)
{
    DIR            *dir;
    struct dirent  *entry;
    ngx_str_t      *site;
    u_char         *path;
    size_t          len;

    path = ngx_pnalloc(pool, sites_enabled_path->len + 1);
    if (path == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(path, sites_enabled_path->data, sites_enabled_path->len);
    path[sites_enabled_path->len] = '\0';

    dir = opendir((char *) path);
    if (dir == NULL) {
        return NGX_ERROR;
    }

    while ((entry = readdir(dir)) != NULL) {
        /* Skip . and .. */
        if (entry->d_name[0] == '.') {
            continue;
        }

        /* Only include symlinks */
        if (entry->d_type != DT_LNK) {
            continue;
        }

        site = ngx_array_push(enabled_sites);
        if (site == NULL) {
            closedir(dir);
            return NGX_ERROR;
        }

        len = ngx_strlen(entry->d_name);
        site->data = ngx_pnalloc(pool, len + 1);
        if (site->data == NULL) {
            closedir(dir);
            return NGX_ERROR;
        }

        ngx_memcpy(site->data, entry->d_name, len);
        site->data[len] = '\0';
        site->len = len;
    }

    closedir(dir);
    return NGX_OK;
}

/* Read complete configuration set */
ngx_int_t
ngx_config_sync_read_config_set(ngx_pool_t *pool,
    ngx_http_config_sync_loc_conf_t *conf, ngx_config_set_t *config_set)
{
    ngx_array_t      *site_files;
    ngx_str_t        *site_name;
    ngx_config_file_t *site_config;
    ngx_str_t         full_path;
    ngx_uint_t        i;
    u_char           *p;

    /* Read main config */
    if (ngx_config_sync_read_file(pool, &conf->main_config_path,
                                  &config_set->main_config) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Initialize arrays */
    config_set->site_configs = ngx_array_create(pool, 8, sizeof(ngx_config_file_t));
    if (config_set->site_configs == NULL) {
        return NGX_ERROR;
    }

    config_set->enabled_sites = ngx_array_create(pool, 8, sizeof(ngx_str_t));
    if (config_set->enabled_sites == NULL) {
        return NGX_ERROR;
    }

    /* List site config files */
    site_files = ngx_array_create(pool, 8, sizeof(ngx_str_t));
    if (site_files == NULL) {
        return NGX_ERROR;
    }

    if (ngx_config_sync_list_dir(pool, &conf->sites_available_path, site_files) != NGX_OK) {
        /* Directory might not exist, which is OK */
        site_files->nelts = 0;
    }

    /* Read each site config */
    site_name = site_files->elts;
    for (i = 0; i < site_files->nelts; i++) {
        site_config = ngx_array_push(config_set->site_configs);
        if (site_config == NULL) {
            return NGX_ERROR;
        }

        /* Build full path */
        full_path.len = conf->sites_available_path.len + 1 + site_name[i].len;
        p = ngx_pnalloc(pool, full_path.len + 1);
        if (p == NULL) {
            return NGX_ERROR;
        }
        full_path.data = p;
        p = ngx_sprintf(p, "%V/%V", &conf->sites_available_path, &site_name[i]);
        *p = '\0';

        if (ngx_config_sync_read_file(pool, &full_path, site_config) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    /* Get enabled sites */
    if (ngx_config_sync_get_enabled_sites(pool, &conf->sites_enabled_path,
                                          config_set->enabled_sites) != NGX_OK) {
        /* Directory might not exist, which is OK */
        config_set->enabled_sites->nelts = 0;
    }

    return NGX_OK;
}

/* Write complete configuration set */
ngx_int_t
ngx_config_sync_write_config_set(ngx_pool_t *pool,
    ngx_http_config_sync_loc_conf_t *conf, ngx_config_set_t *config_set)
{
    ngx_config_file_t *site_config;
    ngx_str_t          full_path;
    ngx_uint_t         i;
    u_char            *p;

    /* Write main config */
    if (ngx_config_sync_write_file(pool, &conf->main_config_path,
                                   &config_set->main_config.content) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Write site configs */
    site_config = config_set->site_configs->elts;
    for (i = 0; i < config_set->site_configs->nelts; i++) {
        /* Extract filename from path */
        u_char *filename = site_config[i].path.data;
        u_char *slash = (u_char *) strrchr((char *)filename, '/');
        if (slash != NULL) {
            filename = slash + 1;
        }

        /* Build full path */
        full_path.len = conf->sites_available_path.len + 1 + ngx_strlen(filename);
        p = ngx_pnalloc(pool, full_path.len + 1);
        if (p == NULL) {
            return NGX_ERROR;
        }
        full_path.data = p;
        p = ngx_sprintf(p, "%V/%s", &conf->sites_available_path, filename);
        *p = '\0';

        if (ngx_config_sync_write_file(pool, &full_path,
                                       &site_config[i].content) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

/* Enable site by creating symlink */
ngx_int_t
ngx_config_sync_enable_site(ngx_pool_t *pool,
    ngx_http_config_sync_loc_conf_t *conf, ngx_str_t *site_name)
{
    u_char  source[NGX_MAX_PATH];
    u_char  target[NGX_MAX_PATH];

    ngx_snprintf(source, NGX_MAX_PATH, "%V/%V%Z",
                 &conf->sites_available_path, site_name);
    ngx_snprintf(target, NGX_MAX_PATH, "%V/%V%Z",
                 &conf->sites_enabled_path, site_name);

    /* Check if source exists */
    if (ngx_file_info(source, NULL) == NGX_FILE_ERROR) {
        return NGX_ERROR;
    }

    /* Remove existing symlink if any */
    unlink((char *) target);

    /* Create symlink */
    if (symlink((char *) source, (char *) target) != 0) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* Disable site by removing symlink */
ngx_int_t
ngx_config_sync_disable_site(ngx_pool_t *pool,
    ngx_http_config_sync_loc_conf_t *conf, ngx_str_t *site_name)
{
    u_char  target[NGX_MAX_PATH];

    ngx_snprintf(target, NGX_MAX_PATH, "%V/%V%Z",
                 &conf->sites_enabled_path, site_name);

    /* Remove symlink */
    if (unlink((char *) target) != 0) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* Validate configuration syntax by calling nginx -t */
ngx_int_t
ngx_config_sync_validate_config(ngx_pool_t *pool,
    ngx_str_t *config_path, ngx_str_t *error_msg)
{
    FILE       *fp;
    char        cmd[NGX_MAX_PATH + 64];
    char        buf[1024];
    u_char     *p;
    size_t      len;
    int         status;

    /* Build command: nginx -t -c <config_path> 2>&1 */
    ngx_snprintf((u_char *)cmd, sizeof(cmd), 
                 "nginx -t -c %V 2>&1%Z", config_path);

    /* Execute command */
    fp = popen(cmd, "r");
    if (fp == NULL) {
        error_msg->len = 0;
        error_msg->data = NULL;
        return NGX_ERROR;
    }

    /* Read output */
    len = 0;
    while (fgets(buf + len, sizeof(buf) - len, fp) != NULL) {
        len = ngx_strlen(buf);
        if (len >= sizeof(buf) - 1) {
            break;
        }
    }

    status = pclose(fp);

    if (status != 0) {
        /* Validation failed, copy error message */
        if (len > 0) {
            p = ngx_pnalloc(pool, len + 1);
            if (p != NULL) {
                ngx_memcpy(p, buf, len);
                p[len] = '\0';
                error_msg->data = p;
                error_msg->len = len;
            }
        } else {
            ngx_str_set(error_msg, "Configuration validation failed");
        }
        return NGX_ERROR;
    }

    error_msg->len = 0;
    error_msg->data = NULL;
    return NGX_OK;
}

/* Calculate combined hash for config set */
ngx_int_t
ngx_config_sync_hash_config_set(ngx_pool_t *pool, ngx_config_set_t *config_set,
    ngx_str_t *hash)
{
    SHA256_CTX        ctx;
    unsigned char     md[SHA256_DIGEST_LENGTH];
    u_char           *hex;
    ngx_uint_t        i;
    ngx_config_file_t *site_config;

    SHA256_Init(&ctx);

    /* Hash main config */
    SHA256_Update(&ctx, config_set->main_config.content.data, 
                  config_set->main_config.content.len);

    /* Hash site configs */
    site_config = config_set->site_configs->elts;
    for (i = 0; i < config_set->site_configs->nelts; i++) {
        SHA256_Update(&ctx, site_config[i].content.data, 
                      site_config[i].content.len);
    }

    SHA256_Final(md, &ctx);

    /* Convert to hex string */
    hex = ngx_pnalloc(pool, SHA256_DIGEST_LENGTH * 2 + 1);
    if (hex == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ngx_sprintf(hex + i * 2, "%02x", md[i]);
    }
    hex[SHA256_DIGEST_LENGTH * 2] = '\0';

    hash->data = hex;
    hash->len = SHA256_DIGEST_LENGTH * 2;

    return NGX_OK;
}
