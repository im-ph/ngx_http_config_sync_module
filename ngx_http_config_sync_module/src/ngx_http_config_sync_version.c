/*
 * ngx_http_config_sync_version.c
 * Nginx Configuration Sync Module - Version Manager Implementation
 */

#include "ngx_http_config_sync_version.h"
#include "ngx_http_config_sync_config.h"
#include "ngx_http_config_sync_utils.h"
#include "cjson/cJSON.h"
#include <dirent.h>
#include <sys/stat.h>

/* Generate version ID: v{timestamp}_{hash_prefix} */
ngx_int_t
ngx_config_sync_generate_version_id(ngx_pool_t *pool,
    time_t timestamp, ngx_str_t *hash, ngx_str_t *version_id)
{
    u_char *p;
    size_t  len;

    /* Format: v{timestamp}_{first 8 chars of hash} */
    len = 1 + 20 + 1 + 8;  /* v + max timestamp digits + _ + hash prefix */
    
    p = ngx_pnalloc(pool, len + 1);
    if (p == NULL) {
        return NGX_ERROR;
    }

    version_id->data = p;
    version_id->len = ngx_sprintf(p, "v%T_%.8s", timestamp, hash->data) - p;

    return NGX_OK;
}

/* Create metadata JSON for version */
static ngx_int_t
ngx_config_sync_write_version_metadata(ngx_pool_t *pool,
    ngx_str_t *version_dir, ngx_config_version_t *version,
    ngx_config_set_t *config_set)
{
    cJSON *root, *files_array, *file_obj, *enabled_array;
    char  *json_str;
    ngx_str_t metadata_path, json_content;
    ngx_config_file_t *site_config;
    ngx_str_t *enabled_site;
    ngx_uint_t i;
    u_char *p;

    root = cJSON_CreateObject();
    if (root == NULL) {
        return NGX_ERROR;
    }

    /* Add version info */
    cJSON_AddStringToObject(root, "id", (char *)version->id.data);
    cJSON_AddNumberToObject(root, "timestamp", (double)version->timestamp);
    cJSON_AddStringToObject(root, "hash", (char *)version->hash.data);
    
    if (version->message.len > 0) {
        cJSON_AddStringToObject(root, "message", (char *)version->message.data);
    }

    /* Add files array */
    files_array = cJSON_CreateArray();
    
    /* Main config */
    file_obj = cJSON_CreateObject();
    cJSON_AddStringToObject(file_obj, "path", "nginx.conf");
    cJSON_AddStringToObject(file_obj, "hash", (char *)config_set->main_config.hash.data);
    cJSON_AddItemToArray(files_array, file_obj);

    /* Site configs */
    site_config = config_set->site_configs->elts;
    for (i = 0; i < config_set->site_configs->nelts; i++) {
        u_char *filename = site_config[i].path.data;
        u_char *slash = (u_char *)ngx_strrchr(filename, '/');
        if (slash != NULL) {
            filename = slash + 1;
        }

        file_obj = cJSON_CreateObject();
        cJSON_AddStringToObject(file_obj, "path", (char *)filename);
        cJSON_AddStringToObject(file_obj, "hash", (char *)site_config[i].hash.data);
        cJSON_AddItemToArray(files_array, file_obj);
    }
    cJSON_AddItemToObject(root, "files", files_array);

    /* Add enabled sites */
    enabled_array = cJSON_CreateArray();
    enabled_site = config_set->enabled_sites->elts;
    for (i = 0; i < config_set->enabled_sites->nelts; i++) {
        cJSON_AddItemToArray(enabled_array, 
            cJSON_CreateString((char *)enabled_site[i].data));
    }
    cJSON_AddItemToObject(root, "enabled_sites", enabled_array);

    /* Convert to string */
    json_str = cJSON_Print(root);
    cJSON_Delete(root);

    if (json_str == NULL) {
        return NGX_ERROR;
    }

    /* Write to file */
    metadata_path.len = version_dir->len + sizeof("/metadata.json");
    p = ngx_pnalloc(pool, metadata_path.len);
    if (p == NULL) {
        free(json_str);
        return NGX_ERROR;
    }
    metadata_path.data = p;
    ngx_sprintf(p, "%V/metadata.json%Z", version_dir);
    metadata_path.len = ngx_strlen(p);

    json_content.data = (u_char *)json_str;
    json_content.len = ngx_strlen(json_str);

    ngx_int_t rc = ngx_config_sync_write_file(pool, &metadata_path, &json_content);
    free(json_str);

    return rc;
}

/* Copy file to version directory */
static ngx_int_t
ngx_config_sync_copy_to_version(ngx_pool_t *pool, ngx_str_t *version_dir,
    ngx_str_t *filename, ngx_str_t *content)
{
    ngx_str_t dest_path;
    u_char *p;

    dest_path.len = version_dir->len + 1 + filename->len;
    p = ngx_pnalloc(pool, dest_path.len + 1);
    if (p == NULL) {
        return NGX_ERROR;
    }
    dest_path.data = p;
    ngx_sprintf(p, "%V/%V%Z", version_dir, filename);
    dest_path.len = ngx_strlen(p);

    return ngx_config_sync_write_file(pool, &dest_path, content);
}

/* Create new version */
ngx_int_t
ngx_config_sync_create_version(ngx_pool_t *pool,
    ngx_http_config_sync_loc_conf_t *conf, ngx_config_set_t *config_set,
    ngx_str_t *message, ngx_config_version_t *version)
{
    ngx_str_t version_dir, sites_dir, hash, filename;
    ngx_config_file_t *site_config;
    ngx_uint_t i;
    u_char *p, *slash;

    /* Calculate config set hash */
    if (ngx_config_sync_hash_config_set(pool, config_set, &hash) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Generate version ID */
    version->timestamp = ngx_time();
    if (ngx_config_sync_generate_version_id(pool, version->timestamp, 
                                            &hash, &version->id) != NGX_OK) {
        return NGX_ERROR;
    }

    version->hash = hash;
    if (message != NULL && message->len > 0) {
        version->message = *message;
    } else {
        ngx_str_null(&version->message);
    }

    /* Create version directory */
    version_dir.len = conf->version_store_path.len + 1 + version->id.len;
    p = ngx_pnalloc(pool, version_dir.len + 1);
    if (p == NULL) {
        return NGX_ERROR;
    }
    version_dir.data = p;
    ngx_sprintf(p, "%V/%V%Z", &conf->version_store_path, &version->id);
    version_dir.len = ngx_strlen(p);

    if (ngx_config_sync_mkdir_p(&version_dir) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Create sites-available subdirectory */
    sites_dir.len = version_dir.len + sizeof("/sites-available");
    p = ngx_pnalloc(pool, sites_dir.len);
    if (p == NULL) {
        return NGX_ERROR;
    }
    sites_dir.data = p;
    ngx_sprintf(p, "%V/sites-available%Z", &version_dir);
    sites_dir.len = ngx_strlen(p);

    if (ngx_config_sync_mkdir_p(&sites_dir) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Copy main config */
    ngx_str_set(&filename, "nginx.conf");
    if (ngx_config_sync_copy_to_version(pool, &version_dir, &filename,
                                        &config_set->main_config.content) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Copy site configs */
    site_config = config_set->site_configs->elts;
    for (i = 0; i < config_set->site_configs->nelts; i++) {
        /* Extract filename */
        slash = (u_char *)ngx_strrchr(site_config[i].path.data, '/');
        if (slash != NULL) {
            filename.data = slash + 1;
            filename.len = site_config[i].path.len - (slash + 1 - site_config[i].path.data);
        } else {
            filename = site_config[i].path;
        }

        if (ngx_config_sync_copy_to_version(pool, &sites_dir, &filename,
                                            &site_config[i].content) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    /* Write metadata */
    if (ngx_config_sync_write_version_metadata(pool, &version_dir, version,
                                               config_set) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Cleanup old versions */
    ngx_config_sync_cleanup_versions(pool, conf);

    return NGX_OK;
}

/* Parse version metadata JSON */
static ngx_int_t
ngx_config_sync_parse_version_metadata(ngx_pool_t *pool, ngx_str_t *json_content,
    ngx_config_version_t *version)
{
    cJSON *root, *item;

    root = cJSON_Parse((char *)json_content->data);
    if (root == NULL) {
        return NGX_ERROR;
    }

    /* Parse id */
    item = cJSON_GetObjectItem(root, "id");
    if (item != NULL && cJSON_IsString(item)) {
        ngx_config_sync_str_from_cstr(pool, &version->id, item->valuestring);
    }

    /* Parse timestamp */
    item = cJSON_GetObjectItem(root, "timestamp");
    if (item != NULL && cJSON_IsNumber(item)) {
        version->timestamp = (time_t)item->valuedouble;
    }

    /* Parse hash */
    item = cJSON_GetObjectItem(root, "hash");
    if (item != NULL && cJSON_IsString(item)) {
        ngx_config_sync_str_from_cstr(pool, &version->hash, item->valuestring);
    }

    /* Parse message */
    item = cJSON_GetObjectItem(root, "message");
    if (item != NULL && cJSON_IsString(item)) {
        ngx_config_sync_str_from_cstr(pool, &version->message, item->valuestring);
    } else {
        ngx_str_null(&version->message);
    }

    cJSON_Delete(root);
    return NGX_OK;
}

/* Get version by ID */
ngx_int_t
ngx_config_sync_get_version(ngx_pool_t *pool,
    ngx_http_config_sync_loc_conf_t *conf, ngx_str_t *version_id,
    ngx_config_version_t *version, ngx_config_set_t *config_set)
{
    ngx_str_t version_dir, metadata_path, sites_dir;
    ngx_config_file_t metadata_file;
    ngx_array_t *site_files;
    ngx_str_t *site_name;
    ngx_config_file_t *site_config;
    ngx_str_t full_path;
    ngx_uint_t i;
    u_char *p;

    /* Build version directory path */
    version_dir.len = conf->version_store_path.len + 1 + version_id->len;
    p = ngx_pnalloc(pool, version_dir.len + 1);
    if (p == NULL) {
        return NGX_ERROR;
    }
    version_dir.data = p;
    ngx_sprintf(p, "%V/%V%Z", &conf->version_store_path, version_id);
    version_dir.len = ngx_strlen(p);

    /* Check if version exists */
    if (ngx_config_sync_path_exists(&version_dir) != NGX_OK) {
        return NGX_CONFIG_SYNC_ERR_VERSION_NOT_FOUND;
    }

    /* Read metadata */
    metadata_path.len = version_dir.len + sizeof("/metadata.json");
    p = ngx_pnalloc(pool, metadata_path.len);
    if (p == NULL) {
        return NGX_ERROR;
    }
    metadata_path.data = p;
    ngx_sprintf(p, "%V/metadata.json%Z", &version_dir);
    metadata_path.len = ngx_strlen(p);

    if (ngx_config_sync_read_file(pool, &metadata_path, &metadata_file) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_config_sync_parse_version_metadata(pool, &metadata_file.content, 
                                               version) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Read config set if requested */
    if (config_set != NULL) {
        /* Read main config */
        full_path.len = version_dir.len + sizeof("/nginx.conf");
        p = ngx_pnalloc(pool, full_path.len);
        if (p == NULL) {
            return NGX_ERROR;
        }
        full_path.data = p;
        ngx_sprintf(p, "%V/nginx.conf%Z", &version_dir);
        full_path.len = ngx_strlen(p);

        if (ngx_config_sync_read_file(pool, &full_path, 
                                      &config_set->main_config) != NGX_OK) {
            return NGX_ERROR;
        }

        /* Initialize arrays */
        config_set->site_configs = ngx_array_create(pool, 8, sizeof(ngx_config_file_t));
        config_set->enabled_sites = ngx_array_create(pool, 8, sizeof(ngx_str_t));
        if (config_set->site_configs == NULL || config_set->enabled_sites == NULL) {
            return NGX_ERROR;
        }

        /* Read site configs */
        sites_dir.len = version_dir.len + sizeof("/sites-available");
        p = ngx_pnalloc(pool, sites_dir.len);
        if (p == NULL) {
            return NGX_ERROR;
        }
        sites_dir.data = p;
        ngx_sprintf(p, "%V/sites-available%Z", &version_dir);
        sites_dir.len = ngx_strlen(p);

        site_files = ngx_array_create(pool, 8, sizeof(ngx_str_t));
        if (site_files == NULL) {
            return NGX_ERROR;
        }

        if (ngx_config_sync_list_dir(pool, &sites_dir, site_files) == NGX_OK) {
            site_name = site_files->elts;
            for (i = 0; i < site_files->nelts; i++) {
                site_config = ngx_array_push(config_set->site_configs);
                if (site_config == NULL) {
                    return NGX_ERROR;
                }

                full_path.len = sites_dir.len + 1 + site_name[i].len;
                p = ngx_pnalloc(pool, full_path.len + 1);
                if (p == NULL) {
                    return NGX_ERROR;
                }
                full_path.data = p;
                ngx_sprintf(p, "%V/%V%Z", &sites_dir, &site_name[i]);
                full_path.len = ngx_strlen(p);

                if (ngx_config_sync_read_file(pool, &full_path, site_config) != NGX_OK) {
                    return NGX_ERROR;
                }
            }
        }
    }

    return NGX_OK;
}

/* Compare function for sorting versions by timestamp (descending) */
static int
ngx_config_sync_version_cmp(const void *a, const void *b)
{
    const ngx_config_version_t *va = a;
    const ngx_config_version_t *vb = b;

    if (vb->timestamp > va->timestamp) return 1;
    if (vb->timestamp < va->timestamp) return -1;
    return 0;
}

/* List all versions */
ngx_int_t
ngx_config_sync_list_versions(ngx_pool_t *pool,
    ngx_http_config_sync_loc_conf_t *conf, ngx_array_t *versions)
{
    DIR *dir;
    struct dirent *entry;
    ngx_config_version_t *version;
    ngx_str_t version_id;
    u_char path[NGX_MAX_PATH];

    ngx_snprintf(path, NGX_MAX_PATH, "%V%Z", &conf->version_store_path);

    dir = opendir((char *)path);
    if (dir == NULL) {
        return NGX_ERROR;
    }

    while ((entry = readdir(dir)) != NULL) {
        /* Skip . and .. */
        if (entry->d_name[0] == '.') {
            continue;
        }

        /* Only include directories starting with 'v' */
        if (entry->d_type != DT_DIR || entry->d_name[0] != 'v') {
            continue;
        }

        version = ngx_array_push(versions);
        if (version == NULL) {
            closedir(dir);
            return NGX_ERROR;
        }

        version_id.data = (u_char *)entry->d_name;
        version_id.len = ngx_strlen(entry->d_name);

        if (ngx_config_sync_get_version(pool, conf, &version_id, 
                                        version, NULL) != NGX_OK) {
            /* Skip invalid versions */
            versions->nelts--;
            continue;
        }
    }

    closedir(dir);

    /* Sort by timestamp descending */
    if (versions->nelts > 1) {
        ngx_qsort(versions->elts, versions->nelts, sizeof(ngx_config_version_t),
                  ngx_config_sync_version_cmp);
    }

    return NGX_OK;
}

/* Rollback to specified version */
ngx_int_t
ngx_config_sync_rollback(ngx_pool_t *pool,
    ngx_http_config_sync_loc_conf_t *conf, ngx_str_t *version_id)
{
    ngx_config_version_t version;
    ngx_config_set_t config_set;

    /* Get version with config set */
    if (ngx_config_sync_get_version(pool, conf, version_id, 
                                    &version, &config_set) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Write config set to current location */
    if (ngx_config_sync_write_config_set(pool, conf, &config_set) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Update enabled sites */
    /* First disable all sites */
    ngx_array_t *current_enabled = ngx_array_create(pool, 8, sizeof(ngx_str_t));
    if (current_enabled == NULL) {
        return NGX_ERROR;
    }

    if (ngx_config_sync_get_enabled_sites(pool, &conf->sites_enabled_path,
                                          current_enabled) == NGX_OK) {
        ngx_str_t *site = current_enabled->elts;
        ngx_uint_t i;
        for (i = 0; i < current_enabled->nelts; i++) {
            ngx_config_sync_disable_site(pool, conf, &site[i]);
        }
    }

    /* Enable sites from version */
    ngx_str_t *enabled_site = config_set.enabled_sites->elts;
    ngx_uint_t i;
    for (i = 0; i < config_set.enabled_sites->nelts; i++) {
        ngx_config_sync_enable_site(pool, conf, &enabled_site[i]);
    }

    return NGX_OK;
}

/* Cleanup old versions */
ngx_int_t
ngx_config_sync_cleanup_versions(ngx_pool_t *pool,
    ngx_http_config_sync_loc_conf_t *conf)
{
    ngx_array_t *versions;
    ngx_config_version_t *version;
    ngx_str_t version_dir;
    ngx_uint_t i;
    u_char cmd[NGX_MAX_PATH + 16];
    u_char *p;

    versions = ngx_array_create(pool, 16, sizeof(ngx_config_version_t));
    if (versions == NULL) {
        return NGX_ERROR;
    }

    if (ngx_config_sync_list_versions(pool, conf, versions) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Remove versions beyond max_versions */
    if (versions->nelts > conf->max_versions) {
        version = versions->elts;
        for (i = conf->max_versions; i < versions->nelts; i++) {
            /* Build version directory path */
            version_dir.len = conf->version_store_path.len + 1 + version[i].id.len;
            p = ngx_pnalloc(pool, version_dir.len + 1);
            if (p == NULL) {
                continue;
            }
            version_dir.data = p;
            ngx_sprintf(p, "%V/%V%Z", &conf->version_store_path, &version[i].id);

            /* Remove directory recursively */
            ngx_snprintf(cmd, sizeof(cmd), "rm -rf %s%Z", version_dir.data);
            system((char *)cmd);
        }
    }

    return NGX_OK;
}
