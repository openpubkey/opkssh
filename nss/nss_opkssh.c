/*
 * NSS module for opkssh JIT user provisioning
 * 
 * This NSS module allows OpenSSH to believe that users exist before they are
 * actually created. When a user attempts to SSH, this module reports the user
 * as existing, allowing OpenSSH to proceed to AuthorizedKeysCommand where
 * opkssh can verify credentials and create the user.
 * 
 * Copyright 2025 OpenPubkey
 * Licensed under the Apache License, Version 2.0
 */

#include <nss.h>
#include <pwd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>

/* Configuration file path */
#ifndef CONFIG_FILE
#define CONFIG_FILE "/etc/opk/nss-opkssh.conf"
#endif

/* Default values for virtual users */
#define DEFAULT_UID 65534
#define DEFAULT_GID 65534
#define DEFAULT_HOME_PREFIX "/home"
#define DEFAULT_SHELL "/bin/bash"
#define DEFAULT_GECOS "OPKSSH JIT User"

/* Configuration structure */
struct nss_opkssh_config {
    int enabled;
    uid_t uid;
    gid_t gid;
    char home_prefix[256];
    char shell[256];
    char gecos[256];
};

/* Load configuration from file */
static void load_config(struct nss_opkssh_config *config) {
    FILE *fp;
    char line[512];
    const char *config_file;
    
    /* Allow override for testing */
    config_file = getenv("NSS_OPKSSH_CONFIG");
    if (!config_file) {
        config_file = CONFIG_FILE;
    }
    
    /* Set defaults */
    config->enabled = 0;  /* Disabled by default */
    config->uid = DEFAULT_UID;
    config->gid = DEFAULT_GID;
    strncpy(config->home_prefix, DEFAULT_HOME_PREFIX, sizeof(config->home_prefix) - 1);
    strncpy(config->shell, DEFAULT_SHELL, sizeof(config->shell) - 1);
    strncpy(config->gecos, DEFAULT_GECOS, sizeof(config->gecos) - 1);
    
    fp = fopen(config_file, "r");
    if (!fp) {
        return;  /* Config file doesn't exist, use defaults */
    }
    
    while (fgets(line, sizeof(line), fp)) {
        char key[256], value[256];
        
        /* Skip comments and empty lines */
        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }
        
        if (sscanf(line, "%255s %255s", key, value) == 2) {
            if (strcmp(key, "enabled") == 0) {
                config->enabled = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
            } else if (strcmp(key, "uid") == 0) {
                config->uid = (uid_t)atoi(value);
            } else if (strcmp(key, "gid") == 0) {
                config->gid = (gid_t)atoi(value);
            } else if (strcmp(key, "home_prefix") == 0) {
                strncpy(config->home_prefix, value, sizeof(config->home_prefix) - 1);
            } else if (strcmp(key, "shell") == 0) {
                strncpy(config->shell, value, sizeof(config->shell) - 1);
            } else if (strcmp(key, "gecos") == 0) {
                /* Read rest of line for GECOS which may contain spaces */
                char *gecos_start = strstr(line, value);
                if (gecos_start) {
                    strncpy(config->gecos, gecos_start, sizeof(config->gecos) - 1);
                    /* Remove trailing newline */
                    config->gecos[strcspn(config->gecos, "\n")] = 0;
                }
            }
        }
    }
    
    fclose(fp);
}

/* Check if a real user exists in /etc/passwd */
static int real_user_exists(const char *name) {
    FILE *fp;
    char line[512];
    int found = 0;
    
    fp = fopen("/etc/passwd", "r");
    if (!fp) {
        return 0;
    }
    
    while (fgets(line, sizeof(line), fp)) {
        char *username = strtok(line, ":");
        if (username && strcmp(username, name) == 0) {
            found = 1;
            break;
        }
    }
    
    fclose(fp);
    return found;
}

/* NSS getpwnam_r implementation */
enum nss_status _nss_opkssh_getpwnam_r(
    const char *name,
    struct passwd *pwd,
    char *buffer,
    size_t buflen,
    int *errnop)
{
    struct nss_opkssh_config config;
    char *buf_ptr;
    size_t name_len, home_len, shell_len, gecos_len;
    
    /* Load configuration */
    load_config(&config);
    
    /* If NSS module is disabled, return not found */
    if (!config.enabled) {
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    }
    
    /* If user already exists in /etc/passwd, let the files module handle it */
    if (real_user_exists(name)) {
        *errnop = ENOENT;
        return NSS_STATUS_NOTFOUND;
    }
    
    /* Calculate required buffer space */
    name_len = strlen(name) + 1;
    home_len = strlen(config.home_prefix) + strlen(name) + 2;  /* /home/username */
    shell_len = strlen(config.shell) + 1;
    gecos_len = strlen(config.gecos) + 1;
    
    if (name_len + home_len + shell_len + gecos_len + 1 > buflen) {
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }
    
    /* Fill in the passwd structure */
    buf_ptr = buffer;
    
    /* Username */
    strcpy(buf_ptr, name);
    pwd->pw_name = buf_ptr;
    buf_ptr += name_len;
    
    /* Password (always x for shadow) */
    strcpy(buf_ptr, "x");
    pwd->pw_passwd = buf_ptr;
    buf_ptr += 2;
    
    /* UID and GID */
    pwd->pw_uid = config.uid;
    pwd->pw_gid = config.gid;
    
    /* GECOS */
    strcpy(buf_ptr, config.gecos);
    pwd->pw_gecos = buf_ptr;
    buf_ptr += gecos_len;
    
    /* Home directory */
    snprintf(buf_ptr, home_len, "%s/%s", config.home_prefix, name);
    pwd->pw_dir = buf_ptr;
    buf_ptr += home_len;
    
    /* Shell */
    strcpy(buf_ptr, config.shell);
    pwd->pw_shell = buf_ptr;
    
    return NSS_STATUS_SUCCESS;
}

/* NSS getpwuid_r implementation */
enum nss_status _nss_opkssh_getpwuid_r(
    uid_t uid,
    struct passwd *pwd,
    char *buffer,
    size_t buflen,
    int *errnop)
{
    /* We don't handle UID lookups - let other NSS modules handle it */
    *errnop = ENOENT;
    return NSS_STATUS_NOTFOUND;
}
