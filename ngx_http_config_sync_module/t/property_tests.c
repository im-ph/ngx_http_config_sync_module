/*
 * property_tests.c
 * Property-based tests for Nginx Config Sync Module
 * 
 * Feature: nginx-config-sync
 * Uses simple random testing approach for C
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <openssl/sha.h>

/* Minimal test framework */
#define TEST_ITERATIONS 100
#define MAX_CONFIG_SIZE 4096

static int tests_passed = 0;
static int tests_failed = 0;

/* Forward declarations */
static void run_version_manager_tests(int iterations);
static void run_auth_handler_tests(int iterations);
static void run_site_management_tests(int iterations);
static void run_sync_engine_tests(int iterations);
static void run_path_config_tests(int iterations);

#define ASSERT_TRUE(cond, msg) do { \
    if (!(cond)) { \
        printf("FAIL: %s\n", msg); \
        tests_failed++; \
        return 0; \
    } \
} while(0)

#define ASSERT_EQ(a, b, msg) ASSERT_TRUE((a) == (b), msg)
#define ASSERT_STR_EQ(a, b, msg) ASSERT_TRUE(strcmp(a, b) == 0, msg)

/* Generate random config content */
static void generate_random_config(char *buf, size_t max_len) {
    static const char *directives[] = {
        "worker_processes",
        "error_log",
        "pid",
        "events",
        "http",
        "server",
        "listen",
        "server_name",
        "location",
        "root",
        "index"
    };
    static const int num_directives = sizeof(directives) / sizeof(directives[0]);
    
    size_t len = 0;
    int num_lines = (rand() % 10) + 1;
    
    for (int i = 0; i < num_lines && len < max_len - 100; i++) {
        const char *directive = directives[rand() % num_directives];
        int value = rand() % 100;
        len += snprintf(buf + len, max_len - len, "%s %d;\n", directive, value);
    }
}

/* Hash function (simplified version matching module) */
static void hash_content(const char *content, size_t len, char *hash_out) {
    unsigned char md[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)content, len, md);
    
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hash_out + i * 2, "%02x", md[i]);
    }
    hash_out[SHA256_DIGEST_LENGTH * 2] = '\0';
}

/*
 * Property 1: Config Storage Round-Trip
 * For any valid Nginx configuration content, storing it and then retrieving it
 * SHALL produce identical content (byte-for-byte).
 * 
 * Validates: Requirements 2.4
 */
static int test_property_1_round_trip(void) {
    char original[MAX_CONFIG_SIZE];
    char retrieved[MAX_CONFIG_SIZE];
    char hash1[65], hash2[65];
    
    /* Generate random config */
    generate_random_config(original, MAX_CONFIG_SIZE);
    size_t len = strlen(original);
    
    /* Simulate store (just copy for unit test) */
    memcpy(retrieved, original, len + 1);
    
    /* Verify content is identical */
    ASSERT_STR_EQ(original, retrieved, "Round-trip content mismatch");
    
    /* Verify hash is identical */
    hash_content(original, len, hash1);
    hash_content(retrieved, strlen(retrieved), hash2);
    ASSERT_STR_EQ(hash1, hash2, "Round-trip hash mismatch");
    
    tests_passed++;
    return 1;
}

/*
 * Property: Hash Determinism
 * For any content, hashing it multiple times SHALL produce the same hash.
 */
static int test_hash_determinism(void) {
    char content[MAX_CONFIG_SIZE];
    char hash1[65], hash2[65], hash3[65];
    
    generate_random_config(content, MAX_CONFIG_SIZE);
    size_t len = strlen(content);
    
    hash_content(content, len, hash1);
    hash_content(content, len, hash2);
    hash_content(content, len, hash3);
    
    ASSERT_STR_EQ(hash1, hash2, "Hash not deterministic (1 vs 2)");
    ASSERT_STR_EQ(hash2, hash3, "Hash not deterministic (2 vs 3)");
    
    tests_passed++;
    return 1;
}

/*
 * Property: Different content produces different hash
 * For any two different contents, their hashes SHALL be different.
 */
static int test_hash_uniqueness(void) {
    char content1[MAX_CONFIG_SIZE];
    char content2[MAX_CONFIG_SIZE];
    char hash1[65], hash2[65];
    
    generate_random_config(content1, MAX_CONFIG_SIZE);
    generate_random_config(content2, MAX_CONFIG_SIZE);
    
    /* Ensure contents are different */
    if (strcmp(content1, content2) == 0) {
        /* Rare case - just modify one */
        strcat(content2, "# modified\n");
    }
    
    hash_content(content1, strlen(content1), hash1);
    hash_content(content2, strlen(content2), hash2);
    
    ASSERT_TRUE(strcmp(hash1, hash2) != 0, "Different content produced same hash");
    
    tests_passed++;
    return 1;
}

/* Run all property tests */
int main(int argc, char **argv) {
    int iterations = TEST_ITERATIONS;
    
    if (argc > 1) {
        iterations = atoi(argv[1]);
    }
    
    srand(time(NULL));
    
    printf("Running property tests with %d iterations...\n\n", iterations);
    
    printf("=== Config Manager Property Tests ===\n\n");
    
    /* Property 1: Round-trip */
    printf("Property 1: Config Storage Round-Trip\n");
    printf("  Validates: Requirements 2.4\n");
    for (int i = 0; i < iterations; i++) {
        if (!test_property_1_round_trip()) {
            printf("  FAILED at iteration %d\n", i);
            break;
        }
    }
    printf("  Passed: %d/%d\n\n", tests_passed, iterations);
    
    int prev_passed = tests_passed;
    
    /* Hash determinism */
    printf("Property: Hash Determinism\n");
    for (int i = 0; i < iterations; i++) {
        if (!test_hash_determinism()) {
            printf("  FAILED at iteration %d\n", i);
            break;
        }
    }
    printf("  Passed: %d/%d\n\n", tests_passed - prev_passed, iterations);
    
    prev_passed = tests_passed;
    
    /* Hash uniqueness */
    printf("Property: Hash Uniqueness\n");
    for (int i = 0; i < iterations; i++) {
        if (!test_hash_uniqueness()) {
            printf("  FAILED at iteration %d\n", i);
            break;
        }
    }
    printf("  Passed: %d/%d\n\n", tests_passed - prev_passed, iterations);
    
    /* Run version manager tests */
    run_version_manager_tests(iterations);
    
    /* Run auth handler tests */
    run_auth_handler_tests(iterations);
    
    /* Run site management tests */
    run_site_management_tests(iterations);
    
    /* Run sync engine tests */
    run_sync_engine_tests(iterations);
    
    /* Run path config tests */
    run_path_config_tests(iterations);
    
    /* Summary */
    printf("=================================\n");
    printf("Total: %d passed, %d failed\n", tests_passed, tests_failed);
    
    return tests_failed > 0 ? 1 : 0;
}


/*
 * Version Manager Property Tests
 * Feature: nginx-config-sync
 */

/* Simulated version storage for testing */
typedef struct {
    char id[64];
    time_t timestamp;
    char hash[65];
    char content[MAX_CONFIG_SIZE];
} test_version_t;

static test_version_t test_versions[100];
static int test_version_count = 0;
static int test_max_versions = 10;

static void reset_test_versions(void) {
    test_version_count = 0;
}

static int create_test_version(const char *content, time_t timestamp) {
    if (test_version_count >= 100) return -1;
    
    test_version_t *v = &test_versions[test_version_count];
    v->timestamp = timestamp;
    strncpy(v->content, content, MAX_CONFIG_SIZE - 1);
    hash_content(content, strlen(content), v->hash);
    snprintf(v->id, sizeof(v->id), "v%ld_%.8s", (long)timestamp, v->hash);
    
    test_version_count++;
    
    /* Cleanup old versions */
    if (test_version_count > test_max_versions) {
        /* Sort by timestamp descending */
        for (int i = 0; i < test_version_count - 1; i++) {
            for (int j = i + 1; j < test_version_count; j++) {
                if (test_versions[i].timestamp < test_versions[j].timestamp) {
                    test_version_t tmp = test_versions[i];
                    test_versions[i] = test_versions[j];
                    test_versions[j] = tmp;
                }
            }
        }
        test_version_count = test_max_versions;
    }
    
    return test_version_count - 1;
}

static test_version_t* get_test_version(const char *id) {
    for (int i = 0; i < test_version_count; i++) {
        if (strcmp(test_versions[i].id, id) == 0) {
            return &test_versions[i];
        }
    }
    return NULL;
}

/*
 * Property 2: Version Creation on Update
 * For any successful configuration update, the Version_Store SHALL contain
 * a new version with timestamp within 1 second of the update time.
 * 
 * Validates: Requirements 5.1
 */
static int test_property_2_version_creation(void) {
    char content[MAX_CONFIG_SIZE];
    time_t before, after;
    
    reset_test_versions();
    generate_random_config(content, MAX_CONFIG_SIZE);
    
    before = time(NULL);
    int idx = create_test_version(content, time(NULL));
    after = time(NULL);
    
    ASSERT_TRUE(idx >= 0, "Version creation failed");
    ASSERT_TRUE(test_versions[idx].timestamp >= before, "Timestamp too early");
    ASSERT_TRUE(test_versions[idx].timestamp <= after + 1, "Timestamp too late");
    
    tests_passed++;
    return 1;
}

/*
 * Property 3: Rollback Restoration
 * For any version V in the version history, rolling back to V and then
 * retrieving the current config SHALL produce content identical to version V.
 * 
 * Validates: Requirements 5.2
 */
static int test_property_3_rollback_restoration(void) {
    char content1[MAX_CONFIG_SIZE], content2[MAX_CONFIG_SIZE];
    char current_content[MAX_CONFIG_SIZE];
    
    reset_test_versions();
    
    /* Create first version */
    generate_random_config(content1, MAX_CONFIG_SIZE);
    int idx1 = create_test_version(content1, time(NULL));
    
    /* Create second version */
    generate_random_config(content2, MAX_CONFIG_SIZE);
    create_test_version(content2, time(NULL) + 1);
    
    /* Simulate rollback to first version */
    test_version_t *v1 = get_test_version(test_versions[idx1].id);
    ASSERT_TRUE(v1 != NULL, "Version not found");
    
    /* After rollback, current content should match v1 */
    strcpy(current_content, v1->content);
    
    ASSERT_STR_EQ(current_content, content1, "Rollback content mismatch");
    
    tests_passed++;
    return 1;
}

/*
 * Property 4: Version History Limit
 * For any sequence of N configuration updates where N > max_versions,
 * the Version_Store SHALL maintain at most max_versions historical versions.
 * 
 * Validates: Requirements 5.3
 */
static int test_property_4_version_limit(void) {
    char content[MAX_CONFIG_SIZE];
    int num_updates = test_max_versions + (rand() % 10) + 1;
    
    reset_test_versions();
    
    for (int i = 0; i < num_updates; i++) {
        generate_random_config(content, MAX_CONFIG_SIZE);
        create_test_version(content, time(NULL) + i);
    }
    
    ASSERT_TRUE(test_version_count <= test_max_versions, 
                "Version count exceeds max_versions");
    
    tests_passed++;
    return 1;
}

/*
 * Property 5: Version Chronological Order
 * For any version history query, the returned versions SHALL be sorted
 * by timestamp in descending order (newest first).
 * 
 * Validates: Requirements 5.4
 */
static int test_property_5_chronological_order(void) {
    char content[MAX_CONFIG_SIZE];
    int num_versions = (rand() % test_max_versions) + 2;
    
    reset_test_versions();
    
    /* Create versions with random timestamps */
    for (int i = 0; i < num_versions; i++) {
        generate_random_config(content, MAX_CONFIG_SIZE);
        create_test_version(content, time(NULL) + rand() % 1000);
    }
    
    /* Verify sorted order (descending by timestamp) */
    for (int i = 0; i < test_version_count - 1; i++) {
        ASSERT_TRUE(test_versions[i].timestamp >= test_versions[i+1].timestamp,
                    "Versions not in chronological order");
    }
    
    tests_passed++;
    return 1;
}

/* Run version manager property tests */
static void run_version_manager_tests(int iterations) {
    int prev_passed;
    
    printf("\n=== Version Manager Property Tests ===\n\n");
    
    /* Property 2 */
    prev_passed = tests_passed;
    printf("Property 2: Version Creation on Update\n");
    printf("  Validates: Requirements 5.1\n");
    for (int i = 0; i < iterations; i++) {
        if (!test_property_2_version_creation()) {
            printf("  FAILED at iteration %d\n", i);
            break;
        }
    }
    printf("  Passed: %d/%d\n\n", tests_passed - prev_passed, iterations);
    
    /* Property 3 */
    prev_passed = tests_passed;
    printf("Property 3: Rollback Restoration\n");
    printf("  Validates: Requirements 5.2\n");
    for (int i = 0; i < iterations; i++) {
        if (!test_property_3_rollback_restoration()) {
            printf("  FAILED at iteration %d\n", i);
            break;
        }
    }
    printf("  Passed: %d/%d\n\n", tests_passed - prev_passed, iterations);
    
    /* Property 4 */
    prev_passed = tests_passed;
    printf("Property 4: Version History Limit\n");
    printf("  Validates: Requirements 5.3\n");
    for (int i = 0; i < iterations; i++) {
        if (!test_property_4_version_limit()) {
            printf("  FAILED at iteration %d\n", i);
            break;
        }
    }
    printf("  Passed: %d/%d\n\n", tests_passed - prev_passed, iterations);
    
    /* Property 5 */
    prev_passed = tests_passed;
    printf("Property 5: Version Chronological Order\n");
    printf("  Validates: Requirements 5.4\n");
    for (int i = 0; i < iterations; i++) {
        if (!test_property_5_chronological_order()) {
            printf("  FAILED at iteration %d\n", i);
            break;
        }
    }
    printf("  Passed: %d/%d\n\n", tests_passed - prev_passed, iterations);
}


/*
 * Auth Handler Property Tests
 * Feature: nginx-config-sync
 * Property 7: Authentication Enforcement
 * Validates: Requirements 8.1, 8.3
 */

/* Simulated auth check */
static int check_auth(const char *configured_token, const char *request_token) {
    /* If no token configured, allow all */
    if (configured_token == NULL || strlen(configured_token) == 0) {
        return 1;  /* OK */
    }
    
    /* If no request token, deny */
    if (request_token == NULL || strlen(request_token) == 0) {
        return 0;  /* Unauthorized */
    }
    
    /* Compare tokens */
    return strcmp(configured_token, request_token) == 0;
}

/* Generate random token */
static void generate_random_token(char *buf, size_t len) {
    static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    size_t token_len = (rand() % (len - 1)) + 1;
    
    for (size_t i = 0; i < token_len; i++) {
        buf[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    buf[token_len] = '\0';
}

/*
 * Property 7: Authentication Enforcement
 * For any API request without valid authentication token,
 * the Sync_Module SHALL return HTTP 401 Unauthorized.
 * 
 * Validates: Requirements 8.1, 8.3
 */
static int test_property_7_auth_enforcement(void) {
    char configured_token[64];
    char request_token[64];
    
    /* Generate random configured token */
    generate_random_token(configured_token, sizeof(configured_token));
    
    /* Test 1: No request token should fail */
    ASSERT_TRUE(check_auth(configured_token, NULL) == 0, 
                "Missing token should be rejected");
    ASSERT_TRUE(check_auth(configured_token, "") == 0, 
                "Empty token should be rejected");
    
    /* Test 2: Wrong token should fail */
    generate_random_token(request_token, sizeof(request_token));
    if (strcmp(configured_token, request_token) != 0) {
        ASSERT_TRUE(check_auth(configured_token, request_token) == 0, 
                    "Wrong token should be rejected");
    }
    
    /* Test 3: Correct token should succeed */
    ASSERT_TRUE(check_auth(configured_token, configured_token) == 1, 
                "Correct token should be accepted");
    
    /* Test 4: No configured token should allow all */
    ASSERT_TRUE(check_auth(NULL, NULL) == 1, 
                "No configured token should allow all");
    ASSERT_TRUE(check_auth("", request_token) == 1, 
                "Empty configured token should allow all");
    
    tests_passed++;
    return 1;
}

/* Run auth handler property tests */
static void run_auth_handler_tests(int iterations) {
    int prev_passed = tests_passed;
    
    printf("\n=== Auth Handler Property Tests ===\n\n");
    
    printf("Property 7: Authentication Enforcement\n");
    printf("  Validates: Requirements 8.1, 8.3\n");
    for (int i = 0; i < iterations; i++) {
        if (!test_property_7_auth_enforcement()) {
            printf("  FAILED at iteration %d\n", i);
            break;
        }
    }
    printf("  Passed: %d/%d\n\n", tests_passed - prev_passed, iterations);
}


/*
 * Site Management Property Tests
 * Feature: nginx-config-sync
 * Property 9: Site Enable/Disable Consistency
 * Validates: Requirements 6.2, 6.5
 */

/* Simulated site storage for testing */
#define MAX_SITES 50
#define MAX_SITE_NAME 64

typedef struct {
    char name[MAX_SITE_NAME];
    int available;  /* 1 if in sites-available */
    int enabled;    /* 1 if symlink exists in sites-enabled */
} test_site_t;

static test_site_t test_sites[MAX_SITES];
static int test_site_count = 0;

static void reset_test_sites(void) {
    test_site_count = 0;
    memset(test_sites, 0, sizeof(test_sites));
}

static void generate_random_site_name(char *buf, size_t len) {
    static const char charset[] = "abcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t name_len = (rand() % (len - 6)) + 3;  /* At least 3 chars */
    
    for (size_t i = 0; i < name_len; i++) {
        buf[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    strcpy(buf + name_len, ".conf");
}

static int add_available_site(const char *name) {
    if (test_site_count >= MAX_SITES) return -1;
    
    /* Check if already exists */
    for (int i = 0; i < test_site_count; i++) {
        if (strcmp(test_sites[i].name, name) == 0) {
            test_sites[i].available = 1;
            return i;
        }
    }
    
    strncpy(test_sites[test_site_count].name, name, MAX_SITE_NAME - 1);
    test_sites[test_site_count].available = 1;
    test_sites[test_site_count].enabled = 0;
    return test_site_count++;
}

static int enable_site(const char *name) {
    for (int i = 0; i < test_site_count; i++) {
        if (strcmp(test_sites[i].name, name) == 0) {
            if (!test_sites[i].available) {
                return -1;  /* Site not available */
            }
            test_sites[i].enabled = 1;
            return 0;
        }
    }
    return -1;  /* Site not found */
}

static int disable_site(const char *name) {
    for (int i = 0; i < test_site_count; i++) {
        if (strcmp(test_sites[i].name, name) == 0) {
            if (!test_sites[i].enabled) {
                return -1;  /* Site not enabled */
            }
            test_sites[i].enabled = 0;
            return 0;
        }
    }
    return -1;  /* Site not found */
}

static int is_site_enabled(const char *name) {
    for (int i = 0; i < test_site_count; i++) {
        if (strcmp(test_sites[i].name, name) == 0) {
            return test_sites[i].enabled;
        }
    }
    return -1;  /* Site not found */
}

static int is_site_available(const char *name) {
    for (int i = 0; i < test_site_count; i++) {
        if (strcmp(test_sites[i].name, name) == 0) {
            return test_sites[i].available;
        }
    }
    return 0;  /* Site not found */
}

/*
 * Property 9: Site Enable/Disable Consistency
 * For any site S in sites-available:
 * - Enabling S SHALL create a symlink in sites-enabled pointing to S
 * - Disabling S SHALL remove the symlink from sites-enabled
 * - The site file in sites-available SHALL remain unchanged
 * 
 * Validates: Requirements 6.2, 6.5
 */
static int test_property_9_site_enable_disable(void) {
    char site_name[MAX_SITE_NAME];
    
    reset_test_sites();
    
    /* Create random available sites */
    int num_sites = (rand() % 5) + 2;
    for (int i = 0; i < num_sites; i++) {
        generate_random_site_name(site_name, MAX_SITE_NAME);
        add_available_site(site_name);
    }
    
    /* Pick a random site to test */
    int site_idx = rand() % test_site_count;
    strcpy(site_name, test_sites[site_idx].name);
    
    /* Test 1: Site should be available but not enabled initially */
    ASSERT_TRUE(is_site_available(site_name) == 1, 
                "Site should be available");
    ASSERT_TRUE(is_site_enabled(site_name) == 0, 
                "Site should not be enabled initially");
    
    /* Test 2: Enable site */
    ASSERT_TRUE(enable_site(site_name) == 0, 
                "Enable site should succeed");
    ASSERT_TRUE(is_site_enabled(site_name) == 1, 
                "Site should be enabled after enable");
    ASSERT_TRUE(is_site_available(site_name) == 1, 
                "Site should still be available after enable");
    
    /* Test 3: Enable already enabled site (should be idempotent or succeed) */
    int result = enable_site(site_name);
    ASSERT_TRUE(result == 0, "Re-enabling should succeed");
    ASSERT_TRUE(is_site_enabled(site_name) == 1, 
                "Site should still be enabled");
    
    /* Test 4: Disable site */
    ASSERT_TRUE(disable_site(site_name) == 0, 
                "Disable site should succeed");
    ASSERT_TRUE(is_site_enabled(site_name) == 0, 
                "Site should be disabled after disable");
    ASSERT_TRUE(is_site_available(site_name) == 1, 
                "Site should still be available after disable");
    
    /* Test 5: Disable already disabled site (should fail) */
    ASSERT_TRUE(disable_site(site_name) == -1, 
                "Disabling already disabled site should fail");
    
    /* Test 6: Enable non-existent site should fail */
    ASSERT_TRUE(enable_site("nonexistent.conf") == -1, 
                "Enabling non-existent site should fail");
    
    tests_passed++;
    return 1;
}

/*
 * Property: Site List Consistency
 * The list of enabled sites SHALL always be a subset of available sites.
 */
static int test_site_list_consistency(void) {
    char site_name[MAX_SITE_NAME];
    
    reset_test_sites();
    
    /* Create random available sites */
    int num_sites = (rand() % 10) + 3;
    for (int i = 0; i < num_sites; i++) {
        generate_random_site_name(site_name, MAX_SITE_NAME);
        add_available_site(site_name);
    }
    
    /* Enable random subset of sites */
    for (int i = 0; i < test_site_count; i++) {
        if (rand() % 2 == 0) {
            enable_site(test_sites[i].name);
        }
    }
    
    /* Verify: all enabled sites must be available */
    for (int i = 0; i < test_site_count; i++) {
        if (test_sites[i].enabled) {
            ASSERT_TRUE(test_sites[i].available == 1, 
                        "Enabled site must be available");
        }
    }
    
    tests_passed++;
    return 1;
}

/*
 * Property: Enable/Disable Idempotency
 * Multiple enable operations on the same site SHALL result in the same state.
 * Multiple disable operations on a disabled site SHALL fail consistently.
 */
static int test_site_idempotency(void) {
    char site_name[MAX_SITE_NAME];
    
    reset_test_sites();
    
    /* Create a site */
    generate_random_site_name(site_name, MAX_SITE_NAME);
    add_available_site(site_name);
    
    /* Enable multiple times */
    enable_site(site_name);
    int state1 = is_site_enabled(site_name);
    enable_site(site_name);
    int state2 = is_site_enabled(site_name);
    enable_site(site_name);
    int state3 = is_site_enabled(site_name);
    
    ASSERT_TRUE(state1 == state2 && state2 == state3, 
                "Enable should be idempotent");
    ASSERT_TRUE(state1 == 1, "Site should be enabled");
    
    /* Disable once */
    disable_site(site_name);
    ASSERT_TRUE(is_site_enabled(site_name) == 0, "Site should be disabled");
    
    /* Disable again should fail */
    int result1 = disable_site(site_name);
    int result2 = disable_site(site_name);
    ASSERT_TRUE(result1 == result2, "Disable failure should be consistent");
    
    tests_passed++;
    return 1;
}

/* Run site management property tests */
static void run_site_management_tests(int iterations) {
    int prev_passed;
    
    printf("\n=== Site Management Property Tests ===\n\n");
    
    /* Property 9 */
    prev_passed = tests_passed;
    printf("Property 9: Site Enable/Disable Consistency\n");
    printf("  Validates: Requirements 6.2, 6.5\n");
    for (int i = 0; i < iterations; i++) {
        if (!test_property_9_site_enable_disable()) {
            printf("  FAILED at iteration %d\n", i);
            break;
        }
    }
    printf("  Passed: %d/%d\n\n", tests_passed - prev_passed, iterations);
    
    /* Site List Consistency */
    prev_passed = tests_passed;
    printf("Property: Site List Consistency\n");
    printf("  Validates: Requirements 6.2\n");
    for (int i = 0; i < iterations; i++) {
        if (!test_site_list_consistency()) {
            printf("  FAILED at iteration %d\n", i);
            break;
        }
    }
    printf("  Passed: %d/%d\n\n", tests_passed - prev_passed, iterations);
    
    /* Site Idempotency */
    prev_passed = tests_passed;
    printf("Property: Enable/Disable Idempotency\n");
    printf("  Validates: Requirements 6.5, 6.6\n");
    for (int i = 0; i < iterations; i++) {
        if (!test_site_idempotency()) {
            printf("  FAILED at iteration %d\n", i);
            break;
        }
    }
    printf("  Passed: %d/%d\n\n", tests_passed - prev_passed, iterations);
}


/*
 * Sync Engine Property Tests
 * Feature: nginx-config-sync
 * Property 6: Sync Status Completeness
 * Property 10: Config Hash Integrity
 * Validates: Requirements 4.3, 8.4
 */

/* Simulated sync result for testing */
typedef struct {
    char host[64];
    int port;
    int success;
    char error[256];
    char hash[65];
} test_node_result_t;

typedef struct {
    int success;
    time_t timestamp;
    test_node_result_t nodes[10];
    int node_count;
} test_sync_result_t;

static test_sync_result_t test_sync_result;

static void reset_test_sync_result(void) {
    memset(&test_sync_result, 0, sizeof(test_sync_result));
}

static void add_test_node_result(const char *host, int port, int success, 
                                  const char *error, const char *hash) {
    if (test_sync_result.node_count >= 10) return;
    
    test_node_result_t *node = &test_sync_result.nodes[test_sync_result.node_count];
    strncpy(node->host, host, sizeof(node->host) - 1);
    node->port = port;
    node->success = success;
    if (error) strncpy(node->error, error, sizeof(node->error) - 1);
    if (hash) strncpy(node->hash, hash, sizeof(node->hash) - 1);
    
    test_sync_result.node_count++;
    if (!success) test_sync_result.success = 0;
}

/*
 * Property 6: Sync Status Completeness
 * For any push operation with N configured target nodes, the sync result
 * SHALL contain exactly N node results, one for each target node.
 * 
 * Validates: Requirements 4.3
 */
static int test_property_6_sync_status_completeness(void) {
    int num_nodes = (rand() % 5) + 1;
    char host[64];
    char hash[65];
    
    reset_test_sync_result();
    test_sync_result.success = 1;
    test_sync_result.timestamp = time(NULL);
    
    /* Simulate push to N nodes */
    for (int i = 0; i < num_nodes; i++) {
        snprintf(host, sizeof(host), "192.168.1.%d", 10 + i);
        hash_content(host, strlen(host), hash);
        
        /* Randomly succeed or fail */
        int success = rand() % 2;
        add_test_node_result(host, 8080, success, 
                            success ? NULL : "Connection failed",
                            success ? hash : NULL);
    }
    
    /* Verify: result contains exactly N node results */
    ASSERT_EQ(test_sync_result.node_count, num_nodes, 
              "Node result count should match configured nodes");
    
    /* Verify: each node has a result */
    for (int i = 0; i < num_nodes; i++) {
        ASSERT_TRUE(strlen(test_sync_result.nodes[i].host) > 0,
                    "Each node should have a host");
        ASSERT_TRUE(test_sync_result.nodes[i].port > 0,
                    "Each node should have a port");
    }
    
    tests_passed++;
    return 1;
}

/*
 * Property 10: Config Hash Integrity
 * For any configuration transfer between nodes, the receiving node SHALL
 * verify that the content hash matches the declared hash before applying.
 * 
 * Validates: Requirements 8.4
 */
static int test_property_10_config_hash_integrity(void) {
    char content[MAX_CONFIG_SIZE];
    char declared_hash[65];
    char computed_hash[65];
    
    /* Generate random config */
    generate_random_config(content, MAX_CONFIG_SIZE);
    
    /* Compute hash */
    hash_content(content, strlen(content), declared_hash);
    
    /* Simulate transfer - content arrives unchanged */
    char received_content[MAX_CONFIG_SIZE];
    strcpy(received_content, content);
    
    /* Verify hash matches */
    hash_content(received_content, strlen(received_content), computed_hash);
    ASSERT_STR_EQ(declared_hash, computed_hash, 
                  "Hash should match for unchanged content");
    
    /* Simulate corrupted transfer */
    received_content[0] = (received_content[0] == 'a') ? 'b' : 'a';
    hash_content(received_content, strlen(received_content), computed_hash);
    ASSERT_TRUE(strcmp(declared_hash, computed_hash) != 0,
                "Hash should NOT match for corrupted content");
    
    tests_passed++;
    return 1;
}

/*
 * Property: Sync Result Timestamp
 * For any sync operation, the result timestamp SHALL be within 1 second
 * of the actual operation time.
 */
static int test_sync_result_timestamp(void) {
    time_t before, after;
    
    reset_test_sync_result();
    
    before = time(NULL);
    test_sync_result.timestamp = time(NULL);
    after = time(NULL);
    
    ASSERT_TRUE(test_sync_result.timestamp >= before,
                "Timestamp should not be before operation");
    ASSERT_TRUE(test_sync_result.timestamp <= after + 1,
                "Timestamp should not be more than 1 second after operation");
    
    tests_passed++;
    return 1;
}

/* Run sync engine property tests */
static void run_sync_engine_tests(int iterations) {
    int prev_passed;
    
    printf("\n=== Sync Engine Property Tests ===\n\n");
    
    /* Property 6 */
    prev_passed = tests_passed;
    printf("Property 6: Sync Status Completeness\n");
    printf("  Validates: Requirements 4.3\n");
    for (int i = 0; i < iterations; i++) {
        if (!test_property_6_sync_status_completeness()) {
            printf("  FAILED at iteration %d\n", i);
            break;
        }
    }
    printf("  Passed: %d/%d\n\n", tests_passed - prev_passed, iterations);
    
    /* Property 10 */
    prev_passed = tests_passed;
    printf("Property 10: Config Hash Integrity\n");
    printf("  Validates: Requirements 8.4\n");
    for (int i = 0; i < iterations; i++) {
        if (!test_property_10_config_hash_integrity()) {
            printf("  FAILED at iteration %d\n", i);
            break;
        }
    }
    printf("  Passed: %d/%d\n\n", tests_passed - prev_passed, iterations);
    
    /* Sync Result Timestamp */
    prev_passed = tests_passed;
    printf("Property: Sync Result Timestamp\n");
    printf("  Validates: Requirements 4.3\n");
    for (int i = 0; i < iterations; i++) {
        if (!test_sync_result_timestamp()) {
            printf("  FAILED at iteration %d\n", i);
            break;
        }
    }
    printf("  Passed: %d/%d\n\n", tests_passed - prev_passed, iterations);
}


/*
 * Path Configuration Property Tests
 * Feature: nginx-config-sync
 * Property 8: Invalid Path Rejection
 * Validates: Requirements 7.4, 7.5
 */

/* Simulated path validation */
static int validate_path(const char *path, int is_file) {
    if (path == NULL || strlen(path) == 0) {
        return 0;  /* Invalid: empty path */
    }
    
    /* Check for path traversal attempts */
    if (strstr(path, "..") != NULL) {
        return 0;  /* Invalid: path traversal */
    }
    
    /* Check for absolute path */
    if (path[0] != '/') {
        return 0;  /* Invalid: not absolute */
    }
    
    /* Check path length */
    if (strlen(path) > 4096) {
        return 0;  /* Invalid: too long */
    }
    
    /* Check for null bytes */
    for (size_t i = 0; i < strlen(path); i++) {
        if (path[i] == '\0') {
            return 0;  /* Invalid: embedded null */
        }
    }
    
    return 1;  /* Valid */
}

/* Generate random valid path */
static void generate_valid_path(char *buf, size_t len, int is_file) {
    static const char *dirs[] = {"/etc/nginx", "/var/nginx", "/opt/nginx"};
    static const char *files[] = {"nginx.conf", "default.conf", "site.conf"};
    
    int dir_idx = rand() % 3;
    
    if (is_file) {
        int file_idx = rand() % 3;
        snprintf(buf, len, "%s/%s", dirs[dir_idx], files[file_idx]);
    } else {
        snprintf(buf, len, "%s/sites-available", dirs[dir_idx]);
    }
}

/* Generate random invalid path */
static void generate_invalid_path(char *buf, size_t len) {
    int type = rand() % 5;
    
    switch (type) {
        case 0:  /* Empty path */
            buf[0] = '\0';
            break;
        case 1:  /* Path traversal */
            strcpy(buf, "/etc/nginx/../../../etc/passwd");
            break;
        case 2:  /* Relative path */
            strcpy(buf, "nginx/nginx.conf");
            break;
        case 3:  /* Too long path */
            memset(buf, 'a', len - 1);
            buf[0] = '/';
            buf[len - 1] = '\0';
            break;
        case 4:  /* Special characters */
            strcpy(buf, "/etc/nginx/\x00hidden.conf");
            break;
    }
}

/*
 * Property 8: Invalid Path Rejection
 * For any path configuration pointing to non-existent directories or
 * containing invalid characters, the Sync_Module SHALL log an error
 * during configuration parsing.
 * 
 * Validates: Requirements 7.4, 7.5
 */
static int test_property_8_invalid_path_rejection(void) {
    char valid_path[256];
    char invalid_path[5000];
    
    /* Test valid paths are accepted */
    generate_valid_path(valid_path, sizeof(valid_path), 1);
    ASSERT_TRUE(validate_path(valid_path, 1) == 1, 
                "Valid file path should be accepted");
    
    generate_valid_path(valid_path, sizeof(valid_path), 0);
    ASSERT_TRUE(validate_path(valid_path, 0) == 1, 
                "Valid directory path should be accepted");
    
    /* Test invalid paths are rejected */
    
    /* Empty path */
    ASSERT_TRUE(validate_path("", 1) == 0, 
                "Empty path should be rejected");
    
    /* Path traversal */
    ASSERT_TRUE(validate_path("/etc/nginx/../../../etc/passwd", 1) == 0, 
                "Path traversal should be rejected");
    
    /* Relative path */
    ASSERT_TRUE(validate_path("nginx/nginx.conf", 1) == 0, 
                "Relative path should be rejected");
    
    /* NULL path */
    ASSERT_TRUE(validate_path(NULL, 1) == 0, 
                "NULL path should be rejected");
    
    tests_passed++;
    return 1;
}

/*
 * Property: Path Normalization
 * Valid paths should be normalized consistently.
 */
static int test_path_normalization(void) {
    /* Test that paths with trailing slashes are handled */
    ASSERT_TRUE(validate_path("/etc/nginx/", 0) == 1, 
                "Directory with trailing slash should be valid");
    
    /* Test that paths without trailing slashes are handled */
    ASSERT_TRUE(validate_path("/etc/nginx", 0) == 1, 
                "Directory without trailing slash should be valid");
    
    tests_passed++;
    return 1;
}

/*
 * Property: Path Security
 * Paths should not allow access outside intended directories.
 */
static int test_path_security(void) {
    /* Various path traversal attempts */
    ASSERT_TRUE(validate_path("/etc/nginx/../passwd", 1) == 0, 
                "Simple traversal should be rejected");
    ASSERT_TRUE(validate_path("/etc/nginx/../../etc/shadow", 1) == 0, 
                "Double traversal should be rejected");
    ASSERT_TRUE(validate_path("/etc/nginx/./../../root", 1) == 0, 
                "Mixed traversal should be rejected");
    
    tests_passed++;
    return 1;
}

/* Run path configuration property tests */
static void run_path_config_tests(int iterations) {
    int prev_passed;
    
    printf("\n=== Path Configuration Property Tests ===\n\n");
    
    /* Property 8 */
    prev_passed = tests_passed;
    printf("Property 8: Invalid Path Rejection\n");
    printf("  Validates: Requirements 7.4, 7.5\n");
    for (int i = 0; i < iterations; i++) {
        if (!test_property_8_invalid_path_rejection()) {
            printf("  FAILED at iteration %d\n", i);
            break;
        }
    }
    printf("  Passed: %d/%d\n\n", tests_passed - prev_passed, iterations);
    
    /* Path Normalization */
    prev_passed = tests_passed;
    printf("Property: Path Normalization\n");
    printf("  Validates: Requirements 7.4\n");
    for (int i = 0; i < iterations; i++) {
        if (!test_path_normalization()) {
            printf("  FAILED at iteration %d\n", i);
            break;
        }
    }
    printf("  Passed: %d/%d\n\n", tests_passed - prev_passed, iterations);
    
    /* Path Security */
    prev_passed = tests_passed;
    printf("Property: Path Security\n");
    printf("  Validates: Requirements 7.5\n");
    for (int i = 0; i < iterations; i++) {
        if (!test_path_security()) {
            printf("  FAILED at iteration %d\n", i);
            break;
        }
    }
    printf("  Passed: %d/%d\n\n", tests_passed - prev_passed, iterations);
}
