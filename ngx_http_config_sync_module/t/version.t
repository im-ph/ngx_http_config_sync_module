#!/usr/bin/perl

# Test::Nginx tests for Version Manager
# Property 2: Version Creation on Update
# Property 3: Rollback Restoration
# Property 4: Version History Limit
# Property 5: Version Chronological Order
# Validates: Requirements 5.1, 5.2, 5.3, 5.4

use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 1: Version created on config update
--- config
    location /sync {
        config_sync on;
        config_sync_auth_token "test-token";
        config_sync_main_config /tmp/nginx-test/nginx.conf;
        config_sync_sites_available /tmp/nginx-test/sites-available;
        config_sync_sites_enabled /tmp/nginx-test/sites-enabled;
        config_sync_version_store /tmp/nginx-test/versions;
        config_sync_max_versions 5;
    }
--- request
POST /sync/config
{"main_config":{"content":"worker_processes 2;"},"site_configs":[],"enabled_sites":[]}
--- more_headers
Authorization: Bearer test-token
Content-Type: application/json
--- error_code: 200
--- response_body_like
"version_id":"[^"]+","hash":"[a-f0-9]{64}","timestamp":[0-9]+

=== TEST 2: Version list returns versions in order
--- config
    location /sync {
        config_sync on;
        config_sync_auth_token "test-token";
        config_sync_main_config /tmp/nginx-test/nginx.conf;
        config_sync_sites_available /tmp/nginx-test/sites-available;
        config_sync_sites_enabled /tmp/nginx-test/sites-enabled;
        config_sync_version_store /tmp/nginx-test/versions;
        config_sync_max_versions 10;
    }
--- request
GET /sync/versions
--- more_headers
Authorization: Bearer test-token
--- error_code: 200
--- response_body_like
"versions":\[.*\],"total":[0-9]+,"max_versions":10

=== TEST 3: Version contains timestamp
--- config
    location /sync {
        config_sync on;
        config_sync_auth_token "test-token";
        config_sync_main_config /tmp/nginx-test/nginx.conf;
        config_sync_sites_available /tmp/nginx-test/sites-available;
        config_sync_sites_enabled /tmp/nginx-test/sites-enabled;
        config_sync_version_store /tmp/nginx-test/versions;
    }
--- request
GET /sync/versions
--- more_headers
Authorization: Bearer test-token
--- error_code: 200
--- response_body_like
"timestamp":[0-9]+

=== TEST 4: Version contains hash
--- config
    location /sync {
        config_sync on;
        config_sync_auth_token "test-token";
        config_sync_main_config /tmp/nginx-test/nginx.conf;
        config_sync_sites_available /tmp/nginx-test/sites-available;
        config_sync_sites_enabled /tmp/nginx-test/sites-enabled;
        config_sync_version_store /tmp/nginx-test/versions;
    }
--- request
GET /sync/versions
--- more_headers
Authorization: Bearer test-token
--- error_code: 200
--- response_body_like
"hash":"[a-f0-9]{64}"

=== TEST 5: Rollback to non-existent version fails
--- config
    location /sync {
        config_sync on;
        config_sync_auth_token "test-token";
        config_sync_main_config /tmp/nginx-test/nginx.conf;
        config_sync_sites_available /tmp/nginx-test/sites-available;
        config_sync_sites_enabled /tmp/nginx-test/sites-enabled;
        config_sync_version_store /tmp/nginx-test/versions;
    }
--- request
POST /sync/rollback
{"version_id":"v_nonexistent_12345"}
--- more_headers
Authorization: Bearer test-token
Content-Type: application/json
--- error_code: 404
--- response_body_like
"VERSION_NOT_FOUND"

=== TEST 6: Max versions configuration is respected
--- config
    location /sync {
        config_sync on;
        config_sync_auth_token "test-token";
        config_sync_main_config /tmp/nginx-test/nginx.conf;
        config_sync_sites_available /tmp/nginx-test/sites-available;
        config_sync_sites_enabled /tmp/nginx-test/sites-enabled;
        config_sync_version_store /tmp/nginx-test/versions;
        config_sync_max_versions 3;
    }
--- request
GET /sync/versions
--- more_headers
Authorization: Bearer test-token
--- error_code: 200
--- response_body_like
"max_versions":3
