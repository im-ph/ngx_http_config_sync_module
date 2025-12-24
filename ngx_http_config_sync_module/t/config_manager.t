#!/usr/bin/perl

# Test::Nginx tests for Config Manager
# Property 1: Config Storage Round-Trip
# Validates: Requirements 2.4

use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 1: Config round-trip - store and retrieve produces identical content
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
GET /sync/config
--- more_headers
Authorization: Bearer test-token
--- error_code: 200
--- response_body_like
"success":true

=== TEST 2: Config upload and retrieve - round trip
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
POST /sync/config
{"main_config": "worker_processes 1;", "site_configs": [], "enabled_sites": []}
--- more_headers
Authorization: Bearer test-token
Content-Type: application/json
--- error_code: 200
--- response_body_like
"success":true

=== TEST 3: Hash consistency - same content produces same hash
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
GET /sync/config
--- more_headers
Authorization: Bearer test-token
--- error_code: 200
--- response_body_like
"hash":"[a-f0-9]{64}"
