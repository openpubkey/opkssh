/*
 * Unit tests for NSS opkssh module
 * 
 * Copyright 2025 OpenPubkey
 * Licensed under the Apache License, Version 2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pwd.h>
#include <sys/types.h>
#include <unistd.h>
#include <nss.h>

/* Declare NSS module functions */
extern enum nss_status _nss_opkssh_getpwnam_r(
    const char *name,
    struct passwd *pwd,
    char *buffer,
    size_t buflen,
    int *errnop);

/* Test helper to create config file */
void create_test_config(const char *path, int enabled) {
    FILE *fp = fopen(path, "w");
    assert(fp != NULL);
    
    fprintf(fp, "enabled %s\n", enabled ? "true" : "false");
    fprintf(fp, "uid 65534\n");
    fprintf(fp, "gid 65534\n");
    fprintf(fp, "home_prefix /home\n");
    fprintf(fp, "shell /bin/bash\n");
    fprintf(fp, "gecos OPKSSH JIT User\n");
    
    fclose(fp);
}

/* Test 1: NSS module returns NOTFOUND when disabled */
void test_nss_disabled() {
    printf("Test 1: NSS module returns NOTFOUND when disabled... ");
    
    create_test_config("/tmp/nss-opkssh-test.conf", 0);
    
    struct passwd pwd;
    char buffer[2048];
    int errnop;
    
    enum nss_status status = _nss_opkssh_getpwnam_r(
        "testuser", &pwd, buffer, sizeof(buffer), &errnop);
    
    /* When disabled, should return NOTFOUND */
    assert(status == NSS_STATUS_NOTFOUND);
    
    unlink("/tmp/nss-opkssh-test.conf");
    printf("PASSED\n");
}

/* Test 2: NSS module returns user info when enabled */
void test_nss_enabled() {
    printf("Test 2: NSS module returns user info when enabled... ");
    
    create_test_config("/tmp/nss-opkssh-test.conf", 1);
    
    struct passwd pwd;
    char buffer[2048];
    int errnop;
    
    /* Test with a non-existent user */
    enum nss_status status = _nss_opkssh_getpwnam_r(
        "nonexistentuser123", &pwd, buffer, sizeof(buffer), &errnop);
    
    /* When enabled, should return SUCCESS for non-existent users */
    assert(status == NSS_STATUS_SUCCESS);
    assert(strcmp(pwd.pw_name, "nonexistentuser123") == 0);
    assert(pwd.pw_uid == 65534);
    assert(pwd.pw_gid == 65534);
    assert(strcmp(pwd.pw_shell, "/bin/bash") == 0);
    assert(strstr(pwd.pw_dir, "/home/nonexistentuser123") != NULL);
    
    unlink("/tmp/nss-opkssh-test.conf");
    printf("PASSED\n");
}

/* Test 3: NSS module returns NOTFOUND for existing users */
void test_nss_existing_user() {
    printf("Test 3: NSS module returns NOTFOUND for existing users... ");
    
    create_test_config("/tmp/nss-opkssh-test.conf", 1);
    
    struct passwd pwd;
    char buffer[2048];
    int errnop;
    
    /* Test with root user (always exists) */
    enum nss_status status = _nss_opkssh_getpwnam_r(
        "root", &pwd, buffer, sizeof(buffer), &errnop);
    
    /* Should return NOTFOUND to let files module handle it */
    assert(status == NSS_STATUS_NOTFOUND);
    
    unlink("/tmp/nss-opkssh-test.conf");
    printf("PASSED\n");
}

/* Test 4: NSS module handles buffer too small */
void test_nss_buffer_too_small() {
    printf("Test 4: NSS module handles buffer too small... ");
    
    create_test_config("/tmp/nss-opkssh-test.conf", 1);
    
    struct passwd pwd;
    char buffer[10]; /* Very small buffer */
    int errnop;
    
    enum nss_status status = _nss_opkssh_getpwnam_r(
        "testuser", &pwd, buffer, sizeof(buffer), &errnop);
    
    /* Should return TRYAGAIN when buffer is too small */
    assert(status == NSS_STATUS_TRYAGAIN);
    
    unlink("/tmp/nss-opkssh-test.conf");
    printf("PASSED\n");
}

/* Test 5: NSS module handles missing config file */
void test_nss_no_config() {
    printf("Test 5: NSS module handles missing config file... ");
    
    /* Make sure config file doesn't exist */
    unlink("/tmp/nss-opkssh-test.conf");
    
    struct passwd pwd;
    char buffer[2048];
    int errnop;
    
    enum nss_status status = _nss_opkssh_getpwnam_r(
        "testuser", &pwd, buffer, sizeof(buffer), &errnop);
    
    /* Without config, should default to disabled and return NOTFOUND */
    assert(status == NSS_STATUS_NOTFOUND);
    
    printf("PASSED\n");
}

int main() {
    printf("Running NSS opkssh module unit tests...\n\n");
    
    test_nss_disabled();
    test_nss_enabled();
    test_nss_existing_user();
    test_nss_buffer_too_small();
    test_nss_no_config();
    
    printf("\nAll tests passed!\n");
    return 0;
}
