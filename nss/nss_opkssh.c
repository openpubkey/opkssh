// Copyright 2025 OpenPubkey
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

/*
 * nss_opkssh.c — NSS module for opkssh just-in-time user provisioning.
 *
 * Implements the glibc NSS passwd AND shadow interfaces by querying
 * opkssh-nssd over a Unix domain socket.  The daemon reads /etc/opk/auth_id
 * and synthesises passwd/shadow entries for every principal listed there.
 *
 * The shadow interface (getspnam_r, setspent, getspent_r, endspent) provides
 * synthetic shadow entries with sp_expire=-1 / sp_max=-1 so that pam_unix.so
 * can perform a real account-validity check — returning PAM_SUCCESS — instead
 * of falling back to PAM_IGNORE and then pam_deny.so.  This lets the standard
 * /etc/pam.d/common-account stack work without modification.
 *
 * Installation:
 *   cp libnss_opkssh.so.2 /lib/x86_64-linux-gnu/
 *   ldconfig
 *   # /etc/nsswitch.conf:
 *   #   passwd: files opkssh
 *   #   shadow: files opkssh
 */

#define _GNU_SOURCE
#include <errno.h>
#include <nss.h>
#include <pwd.h>
#include <shadow.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define OPKSSH_SOCKET "/run/opkssh/nss.sock"
#define CONNECT_TIMEOUT_MS 500
#define RESP_BUF_SIZE 4096

/* ------------------------------------------------------------------ */
/* Minimal JSON helpers — no external dependency required.             */
/* ------------------------------------------------------------------ */

/* Returns 1 if the JSON object contains "key": true */
static int json_bool(const char *json, const char *key)
{
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p) return 0;
    p += strlen(needle);
    while (*p == ' ' || *p == ':' || *p == '\t') p++;
    return strncmp(p, "true", 4) == 0;
}

/* Copies the string value of key into buf (NUL-terminated). Returns 1 on success. */
static int json_str(const char *json, const char *key, char *buf, size_t bufsz)
{
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p) return 0;
    p += strlen(needle);
    while (*p == ' ' || *p == ':' || *p == '\t') p++;
    if (*p != '"') return 0;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i < bufsz - 1) {
        if (*p == '\\') { p++; if (!*p) break; }
        buf[i++] = *p++;
    }
    buf[i] = '\0';
    return 1;
}

/*
 * Returns the integer value of key, or def on failure.
 * Handles both positive numbers and negative numbers (e.g. -1 sentinel).
 */
static long json_int(const char *json, const char *key, long def)
{
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p) return def;
    p += strlen(needle);
    while (*p == ' ' || *p == ':' || *p == '\t') p++;
    /* Accept leading '-' for negative values as well as bare digits */
    if (*p != '-' && (*p < '0' || *p > '9')) return def;
    return strtol(p, NULL, 10);
}

/* ------------------------------------------------------------------ */
/* Socket helpers                                                      */
/* ------------------------------------------------------------------ */

static int connect_daemon(void)
{
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = CONNECT_TIMEOUT_MS * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, OPKSSH_SOCKET, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/*
 * Send a NUL-terminated request line and read one response line into resp.
 * Returns 0 on success, -1 on error.
 */
static int do_request(const char *req, char *resp, size_t resp_size)
{
    int fd = connect_daemon();
    if (fd < 0) return -1;

    /* Write request + newline */
    size_t reqlen = strlen(req);
    if (write(fd, req, reqlen) != (ssize_t)reqlen ||
        write(fd, "\n", 1) != 1) {
        close(fd);
        return -1;
    }

    /* Read one response line */
    size_t pos = 0;
    while (pos < resp_size - 1) {
        ssize_t n = read(fd, resp + pos, 1);
        if (n <= 0) break;
        if (resp[pos] == '\n') break;
        pos++;
    }
    resp[pos] = '\0';
    close(fd);
    return pos > 0 ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* Fill a struct passwd from a JSON response line.                     */
/* ------------------------------------------------------------------ */

static enum nss_status fill_passwd(const char *json,
                                    struct passwd *result,
                                    char *buffer, size_t buflen,
                                    int *errnop)
{
    if (!json_bool(json, "found"))
        return NSS_STATUS_NOTFOUND;

    char name[256]  = {0};
    char gecos[512] = {0};
    char dir[512]   = {0};
    char shell[256] = {0};

    if (!json_str(json, "name", name, sizeof(name))) return NSS_STATUS_UNAVAIL;
    json_str(json, "gecos", gecos, sizeof(gecos));
    json_str(json, "dir",   dir,   sizeof(dir));
    json_str(json, "shell", shell, sizeof(shell));

    long uid = json_int(json, "uid", -1);
    long gid = json_int(json, "gid", -1);
    if (uid < 0 || gid < 0) return NSS_STATUS_UNAVAIL;

    /* Pack strings into caller-supplied buffer */
    char *p = buffer;
    size_t rem = buflen;

#define PACK(dst, src)                                       \
    do {                                                     \
        size_t _len = strlen(src) + 1;                      \
        if (rem < _len) { *errnop = ERANGE;                  \
                          return NSS_STATUS_TRYAGAIN; }      \
        memcpy(p, src, _len);                               \
        (dst) = p;                                           \
        p += _len; rem -= _len;                             \
    } while (0)

    PACK(result->pw_name,   name);
    PACK(result->pw_passwd, "x");
    PACK(result->pw_gecos,  gecos);
    PACK(result->pw_dir,    dir);
    PACK(result->pw_shell,  shell);
#undef PACK

    result->pw_uid = (uid_t)uid;
    result->pw_gid = (gid_t)gid;
    return NSS_STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* Fill a struct spwd from a JSON shadow response line.                */
/* ------------------------------------------------------------------ */

static enum nss_status fill_spwd(const char *json,
                                  struct spwd *result,
                                  char *buffer, size_t buflen,
                                  int *errnop)
{
    if (!json_bool(json, "found"))
        return NSS_STATUS_NOTFOUND;

    char name[256]   = {0};
    char passwd[256] = {0};

    if (!json_str(json, "name", name, sizeof(name))) return NSS_STATUS_UNAVAIL;
    if (!json_str(json, "passwd", passwd, sizeof(passwd)))
        strcpy(passwd, "!");   /* safe: dst has 256 bytes, src is 1 char + NUL */

    /* Pack strings into caller-supplied buffer */
    char *p = buffer;
    size_t rem = buflen;

#define SPPACK(dst, src)                                     \
    do {                                                     \
        size_t _len = strlen(src) + 1;                      \
        if (rem < _len) { *errnop = ERANGE;                  \
                          return NSS_STATUS_TRYAGAIN; }      \
        memcpy(p, src, _len);                               \
        (dst) = p;                                           \
        p += _len; rem -= _len;                             \
    } while (0)

    SPPACK(result->sp_namp, name);
    SPPACK(result->sp_pwdp, passwd);
#undef SPPACK

    /* All long shadow fields default to -1 (not set / never expires).
     * This is what the daemon sends for JIT users, so pam_unix.so sees
     * a valid account with no expiry and returns PAM_SUCCESS.           */
    result->sp_lstchg = (long)json_int(json, "lstchg", -1);
    result->sp_min    = (long)json_int(json, "min",    -1);
    result->sp_max    = (long)json_int(json, "max",    -1);
    result->sp_warn   = (long)json_int(json, "warn",   -1);
    result->sp_inact  = (long)json_int(json, "inact",  -1);
    result->sp_expire = (long)json_int(json, "expire", -1);
    result->sp_flag   = (unsigned long)json_int(json, "flag", 0);

    return NSS_STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* Enumeration state (setpwent / getpwent / endpwent)                 */
/* ------------------------------------------------------------------ */

typedef struct {
    char  json[RESP_BUF_SIZE];
} EnumEntry;

static pthread_mutex_t enum_lock  = PTHREAD_MUTEX_INITIALIZER;
static EnumEntry      *enum_list  = NULL;
static size_t          enum_count = 0;
static size_t          enum_pos   = 0;
static int             enum_fd    = -1; /* connection kept open during enumeration */

enum nss_status _nss_opkssh_setpwent(int stayopen)
{
    (void)stayopen;
    pthread_mutex_lock(&enum_lock);

    /* Free any previous state */
    free(enum_list);
    enum_list  = NULL;
    enum_count = 0;
    enum_pos   = 0;

    if (enum_fd >= 0) { close(enum_fd); enum_fd = -1; }

    /* Open a persistent connection and send "list" */
    int fd = connect_daemon();
    if (fd < 0) {
        pthread_mutex_unlock(&enum_lock);
        return NSS_STATUS_UNAVAIL;
    }

    const char *req = "{\"op\":\"list\"}\n";
    if (write(fd, req, strlen(req)) != (ssize_t)strlen(req)) {
        close(fd);
        pthread_mutex_unlock(&enum_lock);
        return NSS_STATUS_UNAVAIL;
    }
    enum_fd = fd;

    /* Read all response lines into enum_list */
    size_t cap = 64;
    enum_list = malloc(cap * sizeof(EnumEntry));
    if (!enum_list) {
        close(enum_fd); enum_fd = -1;
        pthread_mutex_unlock(&enum_lock);
        return NSS_STATUS_UNAVAIL;
    }

    FILE *stream = fdopen(dup(enum_fd), "r");
    if (!stream) {
        close(enum_fd); enum_fd = -1;
        free(enum_list); enum_list = NULL;
        pthread_mutex_unlock(&enum_lock);
        return NSS_STATUS_UNAVAIL;
    }

    char line[RESP_BUF_SIZE];
    while (fgets(line, sizeof(line), stream)) {
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') line[len-1] = '\0';
        if (line[0] == '\0') continue;

        if (enum_count >= cap) {
            cap *= 2;
            EnumEntry *tmp = realloc(enum_list, cap * sizeof(EnumEntry));
            if (!tmp) break;
            enum_list = tmp;
        }
        strncpy(enum_list[enum_count].json, line, RESP_BUF_SIZE - 1);
        enum_list[enum_count].json[RESP_BUF_SIZE - 1] = '\0';
        enum_count++;
    }
    fclose(stream);
    close(enum_fd); enum_fd = -1;

    pthread_mutex_unlock(&enum_lock);
    return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_opkssh_getpwent_r(struct passwd *result,
                                         char *buffer, size_t buflen,
                                         int *errnop)
{
    pthread_mutex_lock(&enum_lock);

    if (!enum_list || enum_pos >= enum_count) {
        pthread_mutex_unlock(&enum_lock);
        return NSS_STATUS_NOTFOUND;
    }

    const char *json = enum_list[enum_pos].json;
    enum_pos++;
    pthread_mutex_unlock(&enum_lock);

    return fill_passwd(json, result, buffer, buflen, errnop);
}

enum nss_status _nss_opkssh_endpwent(void)
{
    pthread_mutex_lock(&enum_lock);
    free(enum_list);
    enum_list  = NULL;
    enum_count = 0;
    enum_pos   = 0;
    if (enum_fd >= 0) { close(enum_fd); enum_fd = -1; }
    pthread_mutex_unlock(&enum_lock);
    return NSS_STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* getpwnam / getpwuid — single-shot lookups                          */
/* ------------------------------------------------------------------ */

enum nss_status _nss_opkssh_getpwnam_r(const char *name,
                                         struct passwd *result,
                                         char *buffer, size_t buflen,
                                         int *errnop)
{
    char req[512];
    snprintf(req, sizeof(req), "{\"op\":\"getpwnam\",\"name\":\"%s\"}", name);

    char resp[RESP_BUF_SIZE];
    if (do_request(req, resp, sizeof(resp)) < 0)
        return NSS_STATUS_UNAVAIL;

    return fill_passwd(resp, result, buffer, buflen, errnop);
}

enum nss_status _nss_opkssh_getpwuid_r(uid_t uid,
                                         struct passwd *result,
                                         char *buffer, size_t buflen,
                                         int *errnop)
{
    char req[128];
    snprintf(req, sizeof(req), "{\"op\":\"getpwuid\",\"uid\":%lu}",
             (unsigned long)uid);

    char resp[RESP_BUF_SIZE];
    if (do_request(req, resp, sizeof(resp)) < 0)
        return NSS_STATUS_UNAVAIL;

    return fill_passwd(resp, result, buffer, buflen, errnop);
}

/* ------------------------------------------------------------------ */
/* Shadow enumeration state (setspent / getspent_r / endspent)        */
/* ------------------------------------------------------------------ */

static pthread_mutex_t sp_enum_lock  = PTHREAD_MUTEX_INITIALIZER;
static EnumEntry      *sp_enum_list  = NULL;
static size_t          sp_enum_count = 0;
static size_t          sp_enum_pos   = 0;

enum nss_status _nss_opkssh_setspent(int stayopen)
{
    (void)stayopen;
    pthread_mutex_lock(&sp_enum_lock);

    free(sp_enum_list);
    sp_enum_list  = NULL;
    sp_enum_count = 0;
    sp_enum_pos   = 0;

    int fd = connect_daemon();
    if (fd < 0) {
        pthread_mutex_unlock(&sp_enum_lock);
        return NSS_STATUS_UNAVAIL;
    }

    const char *req = "{\"op\":\"listsp\"}\n";
    if (write(fd, req, strlen(req)) != (ssize_t)strlen(req)) {
        close(fd);
        pthread_mutex_unlock(&sp_enum_lock);
        return NSS_STATUS_UNAVAIL;
    }

    size_t cap = 64;
    sp_enum_list = malloc(cap * sizeof(EnumEntry));
    if (!sp_enum_list) {
        close(fd);
        pthread_mutex_unlock(&sp_enum_lock);
        return NSS_STATUS_UNAVAIL;
    }

    FILE *stream = fdopen(dup(fd), "r");
    close(fd);
    if (!stream) {
        free(sp_enum_list); sp_enum_list = NULL;
        pthread_mutex_unlock(&sp_enum_lock);
        return NSS_STATUS_UNAVAIL;
    }

    char line[RESP_BUF_SIZE];
    while (fgets(line, sizeof(line), stream)) {
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') line[len-1] = '\0';
        if (line[0] == '\0') continue;

        if (sp_enum_count >= cap) {
            cap *= 2;
            EnumEntry *tmp = realloc(sp_enum_list, cap * sizeof(EnumEntry));
            if (!tmp) break;
            sp_enum_list = tmp;
        }
        strncpy(sp_enum_list[sp_enum_count].json, line, RESP_BUF_SIZE - 1);
        sp_enum_list[sp_enum_count].json[RESP_BUF_SIZE - 1] = '\0';
        sp_enum_count++;
    }
    fclose(stream);

    pthread_mutex_unlock(&sp_enum_lock);
    return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_opkssh_getspent_r(struct spwd *result,
                                         char *buffer, size_t buflen,
                                         int *errnop)
{
    pthread_mutex_lock(&sp_enum_lock);

    if (!sp_enum_list || sp_enum_pos >= sp_enum_count) {
        pthread_mutex_unlock(&sp_enum_lock);
        return NSS_STATUS_NOTFOUND;
    }

    const char *json = sp_enum_list[sp_enum_pos].json;
    sp_enum_pos++;
    pthread_mutex_unlock(&sp_enum_lock);

    return fill_spwd(json, result, buffer, buflen, errnop);
}

enum nss_status _nss_opkssh_endspent(void)
{
    pthread_mutex_lock(&sp_enum_lock);
    free(sp_enum_list);
    sp_enum_list  = NULL;
    sp_enum_count = 0;
    sp_enum_pos   = 0;
    pthread_mutex_unlock(&sp_enum_lock);
    return NSS_STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* getspnam — single-shot shadow lookup                               */
/* ------------------------------------------------------------------ */

enum nss_status _nss_opkssh_getspnam_r(const char *name,
                                         struct spwd *result,
                                         char *buffer, size_t buflen,
                                         int *errnop)
{
    char req[512];
    snprintf(req, sizeof(req), "{\"op\":\"getspnam\",\"name\":\"%s\"}", name);

    char resp[RESP_BUF_SIZE];
    if (do_request(req, resp, sizeof(resp)) < 0)
        return NSS_STATUS_UNAVAIL;

    return fill_spwd(resp, result, buffer, buflen, errnop);
}
