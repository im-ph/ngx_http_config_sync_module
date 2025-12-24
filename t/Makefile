# Test Makefile for Nginx Config Sync Module

CC = gcc
CFLAGS = -Wall -Wextra -g -I../src
LDFLAGS = -lcrypto

# Property tests
property_tests: property_tests.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Run property tests
test-property: property_tests
	./property_tests 100

# Run Test::Nginx tests (requires nginx compiled with module)
test-nginx:
	@echo "Setting up test environment..."
	@mkdir -p /tmp/nginx-test/sites-available
	@mkdir -p /tmp/nginx-test/sites-enabled
	@mkdir -p /tmp/nginx-test/versions
	@echo "worker_processes 1;" > /tmp/nginx-test/nginx.conf
	prove -v *.t

# Run all tests
test: test-property

# Run full test suite (property + integration)
test-all: test-property test-nginx

# Setup test environment
setup-test-env:
	@mkdir -p /tmp/nginx-test/sites-available
	@mkdir -p /tmp/nginx-test/sites-enabled
	@mkdir -p /tmp/nginx-test/versions
	@echo "worker_processes 1;" > /tmp/nginx-test/nginx.conf
	@echo "Test environment created at /tmp/nginx-test/"

clean:
	rm -f property_tests
	rm -rf /tmp/nginx-test

.PHONY: test test-property test-nginx test-all setup-test-env clean
