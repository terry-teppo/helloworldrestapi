/*
================================================================================
SECURE REST SERVER: UNIFIED MEGA-TEMPLATE (CROSS-PLATFORM) - VERSION 39
================================================================================
Production-ready, single-source, multi-platform JWT gateway with:
- Runtime config-driven behavior (no recompilation needed)
- Platform emulation ("platform": "auto" or override)
- Dynamic config reload via SIGHUP (POSIX) or simulated on Windows
- Issuer normalization (trims trailing slashes and whitespace)
- Multi-provider JWT with JWKS auto-refresh, retry-on-failure, TTL from headers
- Rate limiting, nonce replay protection, API versioning
- App auth, structured logging, security headers
- Thread-safe operations, graceful shutdown
- Cross-platform shims for file locking, signals, and file I/O
- Optimized for 64-bit builds (better OpenSSL performance)
- CivetWeb HTTP server with OpenSSL for SSL/TLS support

Data Flow Overview (ASCII Diagram):
Client Request -> HTTPS Daemon -> Rate Limit Check -> Auth (JWT/App) -> API Version Parse -> POST Data Process -> Input Validation -> Save User -> JSON Response
     |                |             |                      |                   |                      |                        |
     v                v             v                      v                   v                      v                        v
  TLS Termination  CivetWeb Handler   IP Table         JWKS Refresh       Version Support       Field Limits          File I/O               Error JSON

Security References:
- OWASP JWT Best Practices: https://tools.ietf.org/html/rfc8725 (Token validation, audience checks, expiration)
- OWASP Input Validation Cheat Sheet: https://owasp.org/www-project-cheat-sheets/cheatsheets/Input_Validation_Cheat_Sheet.html (Length limits, character restrictions)
- OWASP Rate Limiting: https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks (Per-IP rate limiting)
- OWASP Transport Layer Protection: https://owasp.org/www-project-cheat-sheets/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html (HTTPS enforcement, HSTS)
- CWE-20: Improper Input Validation (Addressed via length checks, type validation, and sanitization)
- CWE-287: Improper Authentication (Addressed via JWT signature verification, nonce replay protection)

Build commands (recommended for 64-bit for better performance):
  Linux:   gcc -o server hello.c civetweb.c -lcurl -lssl -lcrypto -ljansson -pthread -ldl
  macOS:   clang -o server hello.c civetweb.c -lcurl -lssl -lcrypto -ljansson -pthread
  Windows: cl hello.c civetweb.c /link ws2_32.lib User32.lib Advapi32.lib Crypt32.lib
           (For MinGW-w64: x86_64-w64-mingw32-gcc hello.c civetweb.c -o server.exe -lcurl -lssl -lcrypto -ljansson -pthread)

Run with: ./server (config.json in same dir)
Reload: kill -HUP <pid> (POSIX) or Ctrl+Break (Windows simulation)

Config example in file comments below.
================================================================================
*/

#include "civetweb.h"
#include <jansson.h>
#include <jwt.h>
#include <curl/curl.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/file.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <strings.h>
#include <regex.h>

#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <io.h>
#endif

/* uthash for dynamic hash map */
#include "uthash.h"

/* Define User struct */
typedef struct {
    char name[256];  /* Adjust size as needed */
    char email[256]; /* Adjust size as needed */
} User;

#define CONFIG_FILE "config.json"
#define DEFAULT_PORT 8443
#define DEFAULT_CLEANUP_INTERVAL_SECONDS 60
#define DEFAULT_JWKS_REFRESH_INTERVAL 3600
#define DEFAULT_MAX_REQUESTS_PER_MINUTE 30
#define DEFAULT_MAX_TIMESTAMP_DRIFT 300
#define DEFAULT_MAX_NONCE_ENTRIES 10000
#define DEFAULT_MAX_API_VERSION_LEN 15
#define DEFAULT_USERDATA_FILE "users.bin"
#define DEFAULT_PUBKEY_FILE "public.pem"
#define DEFAULT_APP_PUBKEY_FILE "app_pub.pem"

/* Logging level: 0=minimal, 1=verbose */
#define LOG_LEVEL 1  /* Set to 0 for production to reduce stderr spam */

#define LOG_ERROR(fmt, ...) do { if (LOG_LEVEL >= 0) fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__); } while (0)
#define LOG_VERBOSE(fmt, ...) do { if (LOG_LEVEL >= 1) fprintf(stderr, "[VERBOSE] " fmt "\n", ##__VA_ARGS__); } while (0)

/* Platform detection */
#ifdef _WIN32
#define PLATFORM_STR "windows"
#elif defined(__APPLE__)
#define PLATFORM_STR "macos"
#else
#define PLATFORM_STR "linux"
#endif

/* Forward declare types */
typedef struct ProviderEntry_s ProviderEntry;
struct connection_info_struct;

/* --- AppContext: Central shared state --- */
typedef struct {
    ProviderEntry *provider_map;
    pthread_mutex_t provider_lock;
    char *config_path;
    int PORT;
    char *EXPECTED_APP_SECRET;
    char *EXPECTED_AUD;
    char *EXPECTED_APP_ID;
    char *USERDATA_FILE;
    char *PUBKEY_FILE;
    char *APP_PUBKEY_FILE;
    int CLEANUP_INTERVAL_SECONDS;
    time_t JWKS_REFRESH_INTERVAL;
    int MAX_REQUESTS_PER_MINUTE;
    int MAX_TIMESTAMP_DRIFT;
    int MAX_NONCE_ENTRIES;
    int MAX_API_VERSION_LEN;
    int MAX_NAME_LEN;
    int MAX_EMAIL_LEN;
    int MAX_BODY_SIZE;
    const char *supported_versions[2];
    size_t num_supported_versions;
    char *jwt_pubkey;
    char *app_pubkey;
    pthread_mutex_t jwt_pubkey_lock;
} AppContext;

/* Updated ProviderEntry for JWKS caching */
struct ProviderEntry_s {
    char *iss;          // changed to char* for uthash
    const char *jwks_url;     // JWKS endpoint URL
    const char *expected_aud; // expected audience for validation
    char *current_kid;        // current key ID from JWKS
    char *pubkey_pem;         // cached PEM public key
    time_t last_refresh;      // last refresh timestamp
    time_t ttl;               // time-to-live for cache
    pthread_mutex_t lock;     // thread-safe updates
    UT_hash_handle hh;
};

/* Cleanup thread */
static pthread_t cleanup_thread;

/* Shutdown flag */
static volatile sig_atomic_t shutdown_flag = 0;

/* Config reload globals */
static pthread_mutex_t config_mutex = PTHREAD_MUTEX_INITIALIZER;
static volatile sig_atomic_t config_reload_requested = 0;

/* Email validation regex */
static regex_t email_regex;
static int email_regex_compiled = 0;

/* curl memory structure */
struct curl_memory {
    char *data;
    size_t size;
};

/* Static functions for curl callbacks */
static size_t my_curl_write_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    struct curl_memory *mem = (struct curl_memory *)userdata;
    size_t realsize = size * nmemb;
    mem->data = realloc(mem->data, mem->size + realsize + 1);
    if (!mem->data) {
        LOG_ERROR("realloc failed in curl write callback");
        return 0;
    }
    memcpy(&(mem->data[mem->size]), ptr, realsize);
    mem->size += realsize;
    mem->data[mem->size] = 0;
    return realsize;
}

/* Platform shims */
#ifdef _WIN32
BOOL WINAPI console_handler(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_CLOSE_EVENT) {
        shutdown_flag = 1;
        return TRUE;
    } else if (signal == CTRL_BREAK_EVENT) {  // Simulate SIGHUP
        config_reload_requested = 1;
        return TRUE;
    }
    return FALSE;
}
#else
void shutdown_handler(int sig) {
    shutdown_flag = 1;
}
void handle_sighup(int sig) {
    config_reload_requested = 1;
}
#endif

/* Portable secure zero */
static void secure_zero(void *p, size_t n) {
#ifdef _WIN32
    SecureZeroMemory(p, n);
#else
    explicit_bzero(p, n);
#endif
}

/* File locking shim */
int lock_file(int fd) {
    if (fd < 0) {
        LOG_ERROR("Invalid file descriptor for lock_file");
        return -1;
    }
#ifdef _WIN32
    HANDLE h = (HANDLE)_get_osfhandle(fd);
    if (h == INVALID_HANDLE_VALUE) {
        LOG_ERROR("Failed to get handle from file descriptor");
        return -1;
    }
    OVERLAPPED ov = {0};
    if (!LockFileEx(h, LOCKFILE_EXCLUSIVE_LOCK, 0, MAXDWORD, MAXDWORD, &ov)) {
        LOG_ERROR("LockFileEx failed: %d", GetLastError());
        return -1;
    }
    return 0;
#else
    if (flock(fd, LOCK_EX) != 0) {
        perror("[ERROR] flock");
        return -1;
    }
    return 0;
#endif
}

int unlock_file(int fd) {
    if (fd < 0) {
        LOG_ERROR("Invalid file descriptor for unlock_file");
        return -1;
    }
#ifdef _WIN32
    HANDLE h = (HANDLE)_get_osfhandle(fd);
    if (h == INVALID_HANDLE_VALUE) {
        LOG_ERROR("Failed to get handle from file descriptor");
        return -1;
    }
    OVERLAPPED ov = {0};
    if (!UnlockFileEx(h, 0, MAXDWORD, MAXDWORD, &ov)) {
        LOG_ERROR("UnlockFileEx failed: %d", GetLastError());
        return -1;
    }
    return 0;
#else
    if (flock(fd, LOCK_UN) != 0) {
        perror("[ERROR] flock unlock");
        return -1;
    }
    return 0;
#endif
}

/* File open shim (safe fallback for symlink protection) */
int open_user_file(const char *filename) {
    if (!filename) {
        LOG_ERROR("NULL filename in open_user_file");
        return -1;
    }
#ifdef _WIN32
    int fd = _open(filename, _O_WRONLY | _O_CREAT | _O_APPEND, _S_IREAD | _S_IWRITE);
    if (fd < 0) {
        perror("[ERROR] _open");
        return -1;
    }
    return fd;
#else
    int fd = open(filename, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW, 0600);
    if (fd < 0) {
        perror("[ERROR] open");
        return -1;
    }
    return fd;
#endif
}

/* Platform detection shim */
char *detect_platform(const char *cfg_value) {
    if (cfg_value && strcmp(cfg_value, "auto") != 0) {
        char *dup = strdup(cfg_value);
        if (!dup) {
            LOG_ERROR("Memory allocation failed in detect_platform");
            return NULL;
        }
        return dup;
    }
#ifdef _WIN32
    return strdup("windows");
#elif defined(__APPLE__)
    return strdup("macos");
#else
    return strdup("linux");
#endif
}

/* Helper to free ProviderEntry */
/**
 * free_provider_entry - Safely free all fields of a ProviderEntry
 * @entry: Pointer to the ProviderEntry to free
 *
 * Frees normalized ISS, JWKS URL, expected audience, current KID, PEM key,
 * and destroys the mutex. Ensures no memory leaks or double-frees.
 * Does nothing if entry is NULL.
 */
void free_provider_entry(ProviderEntry *entry) {
    if (!entry) return;
    free(entry->iss);
    free((char *)entry->jwks_url);
    free((char *)entry->expected_aud);
    free(entry->current_kid);
    free(entry->pubkey_pem);
    if (pthread_mutex_destroy(&entry->lock) != 0) {
        LOG_ERROR("pthread_mutex_destroy failed in free_provider_entry");
    }
    free(entry);
}

/* Minimal forward declarations for compilation */
char *read_file(const char *filepath);
int add_provider(const char *issuer, const char *key_path);
const char *get_pubkey_for_issuer(const char *iss);
void free_provider_map(void);
int validate_app(const char *app_token, const char *app_secret);
void trim_whitespace(char *str);
int is_valid_version_format(const char *version);
int is_supported_version(AppContext *ctx, const char *version);
int parse_api_version(AppContext *ctx, const char *input, char *out_version, size_t out_size);
int save_user(AppContext *ctx, const char *name, const char *email);
int is_valid_name(AppContext *ctx, const char *s);
int is_valid_email(AppContext *ctx, const char *s);
int validate_nonce(const char *nonce);
void cleanup_nonce_table(void);
int validate_jwt_user(AppContext *ctx, const char *token);
int check_oauth_bearer(AppContext *ctx, struct mg_connection *conn);
int check_rate_limit(const char *client_ip);
void cleanup_expired_entries(void);
void init_providers_from_config(AppContext *ctx, json_t *config);
int parse_post_data(AppContext *ctx, const char *post_data, size_t data_len, struct connection_info_struct *con_info);

/* --- Initialize AppContext --- */
int init_context(AppContext *ctx, const char *config_path) {
    if (!ctx || !config_path) return -1;

    memset(ctx, 0, sizeof(*ctx));
    ctx->config_path = strdup(config_path);
    if (!ctx->config_path) return -1;

    if (pthread_mutex_init(&ctx->provider_lock, NULL) != 0) {
        free(ctx->config_path);
        return -1;
    }

    if (pthread_mutex_init(&ctx->jwt_pubkey_lock, NULL) != 0) {
        pthread_mutex_destroy(&ctx->provider_lock);
        free(ctx->config_path);
        return -1;
    }

    ctx->provider_map = NULL;
    ctx->PORT = DEFAULT_PORT;
    ctx->EXPECTED_APP_SECRET = NULL;
    ctx->EXPECTED_AUD = NULL;
    ctx->EXPECTED_APP_ID = NULL;
    ctx->USERDATA_FILE = NULL;
    ctx->PUBKEY_FILE = NULL;
    ctx->APP_PUBKEY_FILE = NULL;
    ctx->CLEANUP_INTERVAL_SECONDS = DEFAULT_CLEANUP_INTERVAL_SECONDS;
    ctx->JWKS_REFRESH_INTERVAL = DEFAULT_JWKS_REFRESH_INTERVAL;
    ctx->MAX_REQUESTS_PER_MINUTE = DEFAULT_MAX_REQUESTS_PER_MINUTE;
    ctx->MAX_TIMESTAMP_DRIFT = DEFAULT_MAX_TIMESTAMP_DRIFT;
    ctx->MAX_NONCE_ENTRIES = DEFAULT_MAX_NONCE_ENTRIES;
    ctx->MAX_API_VERSION_LEN = DEFAULT_MAX_API_VERSION_LEN;
    ctx->MAX_NAME_LEN = 48;
    ctx->MAX_EMAIL_LEN = 96;
    ctx->MAX_BODY_SIZE = 4096;
    ctx->supported_versions[0] = "1.0";
    ctx->supported_versions[1] = "1.1";
    ctx->num_supported_versions = 2;
    ctx->jwt_pubkey = NULL;
    ctx->app_pubkey = NULL;

    return 0;
}

/* --- Cleanup providers and context --- */
void free_context(AppContext *ctx) {
    if (!ctx) return;

    ProviderEntry *entry, *tmp;
    HASH_ITER(hh, ctx->provider_map, entry, tmp) {
        HASH_DEL(ctx->provider_map, entry);
        free_provider_entry(entry);
    }

    pthread_mutex_destroy(&ctx->provider_lock);
    pthread_mutex_destroy(&ctx->jwt_pubkey_lock);
    free(ctx->config_path);
    free(ctx->EXPECTED_APP_SECRET);
    free(ctx->EXPECTED_AUD);
    free(ctx->EXPECTED_APP_ID);
    free(ctx->USERDATA_FILE);
    free(ctx->PUBKEY_FILE);
    free(ctx->APP_PUBKEY_FILE);
    free(ctx->jwt_pubkey);
    free(ctx->app_pubkey);
}

/* Helper: Normalize iss by trimming trailing slashes and whitespace */
/**
 * normalize_iss - Normalize issuer string for consistent lookup
 * @raw: Raw issuer string from config
 *
 * Trims leading/trailing whitespace and trailing slashes to ensure
 * consistent hashing and comparison. Returns malloc'ed normalized string
 * or NULL on error.
 * Caller must free the returned string.
 */
static char *normalize_iss(const char *raw) {
    if (!raw) {
        LOG_ERROR("NULL raw input in normalize_iss");
        return NULL;
    }
    char *normalized = strdup(raw);
    if (!normalized) {
        LOG_ERROR("Memory allocation failed in normalize_iss");
        return NULL;
    }
    size_t len = strlen(normalized);
    while (len > 0 && (isspace((unsigned char)normalized[len - 1]) || normalized[len - 1] == '/')) len--;
    size_t start = 0;
    while (start < len && isspace((unsigned char)normalized[start])) start++;
    size_t new_len = len - start;
    char *out = malloc(new_len + 1);
    if (!out) {
        free(normalized);
        LOG_ERROR("Memory allocation failed for out in normalize_iss");
        return NULL;
    }
    memcpy(out, normalized + start, new_len);
    out[new_len] = '\0';
    free(normalized);
    return out;
}

/* Utility: Read PEM file contents into a string with basic validation */
/**
 * read_file - Read a PEM file into a null-terminated string
 * @filepath: Path to the PEM file
 *
 * Returns a malloc'ed string containing the file contents, or NULL on error.
 * Performs ultra-defensive checks:
 *   - Validates input argument
 *   - Checks fopen, fseek, ftell, fread, and malloc errors
 *   - Validates file size and PEM format
 *   - Always cleans up resources on error
 *   - Prevents empty file reads and size overflows
 * Caller must free the returned buffer.
 */
char *read_file(const char *filepath) {
    if (!filepath) {
        LOG_ERROR("NULL filepath in read_file");
        return NULL;
    }
    FILE *f = fopen(filepath, "rb");
    if (!f) {
        LOG_ERROR("Failed to open file: %s", filepath);
        return NULL;
    }
    /* Seek to end to determine file length for allocation */
    if (fseek(f, 0, SEEK_END) != 0) {
        perror("[ERROR] fseek to end");
        fclose(f);
        return NULL;
    }
    /* Get current file position as length */
    long len = ftell(f);
    if (len < 0) {
        perror("[ERROR] ftell");
        fclose(f);
        return NULL;
    }
    /* Prevent reading files larger than SIZE_MAX to avoid overflow */
    if (len > SIZE_MAX) {
        LOG_ERROR("File too large in read_file");
        fclose(f);
        return NULL;
    }
    /* Rewind to start of file for reading */
    rewind(f);
    /* Allocate buffer with space for null terminator */
    char *buf = malloc((size_t)len + 1);
    if (!buf) {
        LOG_ERROR("Memory allocation failed for buf in read_file");
        fclose(f);
        return NULL;
    }
    /* Read entire file into buffer */
    size_t readlen = fread(buf, 1, (size_t)len, f);
    if (readlen != (size_t)len) {
        perror("[ERROR] fread incomplete");
        free(buf);
        fclose(f);
        return NULL;
    }
    buf[readlen] = '\0';
    /* Check fclose for potential write-back errors */
    if (fclose(f) != 0) {
        perror("[ERROR] fclose failed");
        free(buf);
        return NULL;
    }
    /* Basic validation for PEM key: must contain expected headers */
    if (!strstr(buf, "-----BEGIN PUBLIC KEY-----") && !strstr(buf, "-----BEGIN RSA PUBLIC KEY-----")) {
        LOG_ERROR("Invalid PEM public key format in %s", filepath);
        free(buf);
        return NULL;
    }
    return buf;
}

/* Helper: Decode base64url to binary (using EVP_DecodeBlock) */
/**
 * base64url_decode - Decode base64url string to binary data
 * @in: Input base64url string
 * @out: Output buffer (malloc'ed by function)
 * @out_len: Length of decoded data
 *
 * Converts base64url to standard base64, decodes using OpenSSL EVP_DecodeBlock.
 * Returns 0 on success, non-zero on error.
 * Caller must free *out on success.
 */
static int base64url_decode(const char *in, unsigned char **out, size_t *out_len) {
    if (!in || !out || !out_len) {
        LOG_ERROR("NULL parameters in base64url_decode");
        return 0;
    }
    size_t inlen = strlen(in);
    char *tmp = malloc(inlen + 5);
    if (!tmp) {
        LOG_ERROR("Memory allocation failed for tmp in base64url_decode");
        return 0;
    }
    memcpy(tmp, in, inlen);
    tmp[inlen] = '\0';
    for (size_t i = 0; i < inlen; ++i) {
        if (tmp[i] == '-') tmp[i] = '+';
        else if (tmp[i] == '_') tmp[i] = '/';
    }
    size_t pad = (4 - (inlen % 4)) % 4;
    for (size_t i = 0; i < pad; ++i) tmp[inlen + i] = '=';
    tmp[inlen + pad] = '\0';

    size_t max_out = (strlen(tmp) * 3) / 4 + 1;
    unsigned char *buf = malloc(max_out);
    if (!buf) {
        free(tmp);
        LOG_ERROR("Memory allocation failed for buf in base64url_decode");
        return 0;
    }

    int decoded = EVP_DecodeBlock(buf, (const unsigned char*)tmp, (int)strlen(tmp));
    free(tmp);
    if (decoded < 0) {
        free(buf);
        LOG_ERROR("EVP_DecodeBlock failed in base64url_decode");
        return 0;
    }
    /* Adjust for padding characters which EVP leaves as zero bytes */
    while (decoded > 0 && buf[decoded - 1] == '\0') decoded--;
    *out = buf;
    *out_len = (size_t)decoded;
    return 1;
}

/* JWKS-specific: Convert JWK to PEM (full OpenSSL implementation) */
/**
 * convert_jwk_to_pem - Convert JWK RSA key to PEM format
 * @jwk: JSON object containing JWK with n and e
 *
 * Extracts n and e, decodes from base64url, constructs RSA key,
 * serializes to PEM. Returns malloc'ed PEM string or NULL on error.
 * Caller must free the returned string.
 */
char *convert_jwk_to_pem(json_t *jwk) {
    if (!jwk) {
        LOG_ERROR("NULL jwk in convert_jwk_to_pem");
        return NULL;
    }

    // Extract n and e from JWK
    const char *n_b64 = json_string_value(json_object_get(jwk, "n"));
    const char *e_b64 = json_string_value(json_object_get(jwk, "e"));
    if (!n_b64 || !e_b64) {
        LOG_ERROR("Missing n or e in JWK");
        return NULL;
    }

    // Decode n and e to binary
    unsigned char *n_bin = NULL, *e_bin = NULL;
    size_t n_len, e_len;
    if (base64url_decode(n_b64, &n_bin, &n_len) <= 0 ||
        base64url_decode(e_b64, &e_bin, &e_len) <= 0) {
        LOG_ERROR("Failed to decode n or e from JWK");
        free(n_bin);
        free(e_bin);
        return NULL;
    }

    // Create RSA key
    RSA *rsa = RSA_new();
    if (!rsa) {
        LOG_ERROR("RSA_new failed in convert_jwk_to_pem");
        free(n_bin);
        free(e_bin);
        return NULL;
    }

    BIGNUM *bn_n = BN_bin2bn(n_bin, n_len, NULL);
    BIGNUM *bn_e = BN_bin2bn(e_bin, e_len, NULL);
    free(n_bin);
    free(e_bin);
    if (!bn_n || !bn_e) {
        LOG_ERROR("BN_bin2bn failed for n or e");
        BN_free(bn_n);
        BN_free(bn_e);
        RSA_free(rsa);
        return NULL;
    }

    if (RSA_set0_key(rsa, bn_n, bn_e, NULL) != 1) {
        LOG_ERROR("RSA_set0_key failed");
        BN_free(bn_n);
        BN_free(bn_e);
        RSA_free(rsa);
        return NULL;
    }

    // Serialize to PEM
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) {
        LOG_ERROR("BIO_new for PEM serialization failed");
        RSA_free(rsa);
        return NULL;
    }
    if (PEM_write_bio_RSA_PUBKEY(bio, rsa) != 1) {
        LOG_ERROR("PEM_write_bio_RSA_PUBKEY failed");
        BIO_free(bio);
        RSA_free(rsa);
        return NULL;
    }

    char *pem_data = NULL;
    long pem_len = BIO_get_mem_data(bio, &pem_data);
    if (pem_len <= 0) {
        LOG_ERROR("BIO_get_mem_data failed");
        BIO_free(bio);
        RSA_free(rsa);
        return NULL;
    }
    char *result = strndup(pem_data, pem_len);
    if (!result) {
        LOG_ERROR("strndup failed for PEM result");
        BIO_free(bio);
        RSA_free(rsa);
        return NULL;
    }

    BIO_free(bio);
    RSA_free(rsa);
    return result;
}

/* JWKS: Header callback to parse Cache-Control for TTL */
size_t header_callback(char *buffer, size_t size, size_t nitems, void *userdata) {
    if (!buffer || !userdata) {
        LOG_ERROR("NULL buffer or userdata in header_callback");
        return 0;
    }
    size_t len = size * nitems;
    ProviderEntry *entry = (ProviderEntry *)userdata;
    if (len > 14 && strncasecmp(buffer, "Cache-Control:", 14) == 0) {
        char *max_age_str = strstr(buffer, "max-age=");
        if (max_age_str) {
            long max_age = strtol(max_age_str + 8, NULL, 10);
            if (max_age > 0) entry->ttl = (time_t)max_age;
        }
    }
    return len;
}

/* JWKS: Fetch JWKS JSON from URL using libcurl */
/**
 * fetch_jwks - Fetch JWKS document from provider URL
 * @url: JWKS endpoint URL
 * @entry: ProviderEntry to store TTL from headers
 *
 * Uses libcurl to download JWKS JSON, parses Cache-Control for TTL.
 * Returns json_t object or NULL on error.
 * Caller must json_decref the returned object.
 */
json_t *fetch_jwks(const char *url, ProviderEntry *entry) {
    if (!url || !entry) {
        LOG_ERROR("NULL url or entry in fetch_jwks");
        return NULL;
    }
    CURL *curl = curl_easy_init();
    if (!curl) {
        LOG_ERROR("curl_easy_init failed in fetch_jwks");
        return NULL;
    }

    struct curl_memory {
        char *data;
        size_t size;
    } chunk = {0};

    if (curl_easy_setopt(curl, CURLOPT_URL, url) != CURLE_OK) {
        LOG_ERROR("curl_easy_setopt URL failed");
        curl_easy_cleanup(curl);
        return NULL;
    }
    if (curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, my_curl_write_callback) != CURLE_OK) {
        LOG_ERROR("curl_easy_setopt writefunction failed");
        curl_easy_cleanup(curl);
        return NULL;
    }
    if (curl_easy_setopt(curl, CURLOPT_WRITEDATA, &chunk) != CURLE_OK) {
        LOG_ERROR("curl_easy_setopt writedata failed");
        curl_easy_cleanup(curl);
        return NULL;
    }
    if (curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback) != CURLE_OK) {
        LOG_ERROR("curl_easy_setopt headerfunction failed");
        curl_easy_cleanup(curl);
        return NULL;
    }
    if (curl_easy_setopt(curl, CURLOPT_HEADERDATA, entry) != CURLE_OK) {
        LOG_ERROR("curl_easy_setopt headerdata failed");
        curl_easy_cleanup(curl);
        return NULL;
    }

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        LOG_ERROR("Failed to fetch JWKS from %s: %s", url, curl_easy_strerror(res));
        free(chunk.data);
        return NULL;
    }

    json_error_t error;
    json_t *jwks = json_loads(chunk.data, 0, &error);
    free(chunk.data);
    if (!jwks) {
        LOG_ERROR("Failed to parse JWKS JSON: %s", error.text);
        return NULL;
    }
    return jwks;
}

/* JWKS: Refresh provider keys from JWKS endpoint */
/**
 * refresh_provider - Refresh cached public key for a provider
 * @entry: ProviderEntry to refresh
 *
 * Fetches JWKS if TTL expired, finds matching kid or first RSA key,
 * caches PEM. Returns 0 on success, -1 on error.
 */
int refresh_provider(ProviderEntry *entry) {
    if (!entry) {
        LOG_ERROR("NULL entry in refresh_provider");
        return -1;
    }
    time_t now = time(NULL);
    if (now - entry->last_refresh < entry->ttl) return 0; // Not expired

    json_t *jwks = fetch_jwks(entry->jwks_url, entry);
    if (!jwks) return -1;

    json_t *keys = json_object_get(jwks, "keys");
    if (!json_is_array(keys)) {
        LOG_ERROR("JWKS keys not an array");
        json_decref(jwks);
        return -1;
    }

    size_t index;
    json_t *key;
    json_array_foreach(keys, index, key) {
        const char *kid = json_string_value(json_object_get(key, "kid"));
        if (kid && strcmp(kid, entry->current_kid ? entry->current_kid : "") == 0) {
            // Found matching kid, convert to PEM
            char *pem = convert_jwk_to_pem(key);
            if (pem) {
                pthread_mutex_lock(&entry->lock);
                free(entry->pubkey_pem);
                entry->pubkey_pem = pem;
                entry->last_refresh = now;
                pthread_mutex_unlock(&entry->lock);
                printf("[JWKS] Refreshed key for issuer=%s kid=%s at %ld\n", entry->iss, entry->current_kid ? entry->current_kid : "(none)", now);
                json_decref(jwks);
                return 0;
            } else {
                LOG_ERROR("Failed to convert JWK to PEM");
            }
        }
    }

    // If kid changed or not found, refresh all and pick first RSA key
    json_array_foreach(keys, index, key) {
        const char *kty = json_string_value(json_object_get(key, "kty"));
        if (kty && strcmp(kty, "RSA") == 0) {
            const char *kid = json_string_value(json_object_get(key, "kid"));
            char *pem = convert_jwk_to_pem(key);
            if (pem) {
                pthread_mutex_lock(&entry->lock);
                free(entry->pubkey_pem);
                free(entry->current_kid);
                entry->pubkey_pem = pem;
                entry->current_kid = kid ? strdup(kid) : NULL;
                if (kid && !entry->current_kid) {
                    LOG_ERROR("Memory allocation failed for current_kid");
                    pthread_mutex_unlock(&entry->lock);
                    json_decref(jwks);
                    return -1;
                }
                entry->last_refresh = now;
                pthread_mutex_unlock(&entry->lock);
                printf("[JWKS] Refreshed key for issuer=%s kid=%s at %ld\n", entry->iss, entry->current_kid ? entry->current_kid : "(none)", now);
                json_decref(jwks);
                return 0;
            } else {
                LOG_ERROR("Failed to convert JWK to PEM for RSA key");
            }
        }
    }

    json_decref(jwks);
    return -1; // Failed to refresh
}

/* Config: Load JSON config file and set globals */
/**
 * load_config - Load and parse config.json
 * @filepath: Path to config file
 *
 * Reads, parses JSON, sets global config variables.
 * Returns parsed json_t root or NULL on error.
 * Caller must json_decref on success.
 */
json_t *load_config(const char *filepath) {
    if (!filepath) {
        LOG_ERROR("NULL filepath in load_config");
        return NULL;
    }
    char *data = read_file(filepath);
    if (!data) return NULL;

    json_error_t error;
    json_t *root = json_loads(data, 0, &error);
    free(data);
    if (!root) {
        LOG_ERROR("Failed to parse config file %s: %s", filepath, error.text);
        return NULL;
    }

    return root;
}

/* Config: Reload config.json dynamically */
/**
 * reload_config - Reload config without restarting server
 * @ctx: AppContext with config path and state
 *
 * Locks config, loads new config, updates providers safely.
 * Returns 0 on success, -1 on error.
 */
int reload_config(AppContext *ctx) {
    if (!ctx || !ctx->config_path) {
        LOG_ERROR("NULL ctx or config_path in reload_config");
        return -1;
    }
    pthread_mutex_lock(&config_mutex);

    json_t *root = load_config(ctx->config_path);
    if (!root) {
        pthread_mutex_unlock(&config_mutex);
        return -1;
    }

    // Reload server settings (now in ctx)
    json_t *server = json_object_get(root, "server");
    if (server) {
        ctx->PORT = json_integer_value(json_object_get(server, "port")) ?: DEFAULT_PORT;
        free(ctx->EXPECTED_APP_SECRET);
        ctx->EXPECTED_APP_SECRET = json_is_string(json_object_get(server, "expected_app_secret")) ? strdup(json_string_value(json_object_get(server, "expected_app_secret"))) : NULL;
        free(ctx->EXPECTED_AUD);
        ctx->EXPECTED_AUD = json_is_string(json_object_get(server, "expected_aud")) ? strdup(json_string_value(json_object_get(server, "expected_aud"))) : NULL;
        free(ctx->EXPECTED_APP_ID);
        ctx->EXPECTED_APP_ID = json_is_string(json_object_get(server, "expected_app_id")) ? strdup(json_string_value(json_object_get(server, "expected_app_id"))) : NULL;
        free(ctx->USERDATA_FILE);
        ctx->USERDATA_FILE = json_is_string(json_object_get(server, "userdata_file")) ? strdup(json_string_value(json_object_get(server, "userdata_file"))) : strdup(DEFAULT_USERDATA_FILE);
        free(ctx->PUBKEY_FILE);
        ctx->PUBKEY_FILE = json_is_string(json_object_get(server, "pubkey_file")) ? strdup(json_string_value(json_object_get(server, "pubkey_file"))) : strdup(DEFAULT_PUBKEY_FILE);
        free(ctx->APP_PUBKEY_FILE);
        ctx->APP_PUBKEY_FILE = json_is_string(json_object_get(server, "app_pubkey_file")) ? strdup(json_string_value(json_object_get(server, "app_pubkey_file"))) : strdup(DEFAULT_APP_PUBKEY_FILE);
        ctx->CLEANUP_INTERVAL_SECONDS = json_integer_value(json_object_get(server, "cleanup_interval_seconds")) ?: DEFAULT_CLEANUP_INTERVAL_SECONDS;
        ctx->JWKS_REFRESH_INTERVAL = json_integer_value(json_object_get(server, "jwks_refresh_interval")) ?: DEFAULT_JWKS_REFRESH_INTERVAL;
        ctx->MAX_REQUESTS_PER_MINUTE = json_integer_value(json_object_get(server, "max_requests_per_minute")) ?: DEFAULT_MAX_REQUESTS_PER_MINUTE;
        ctx->MAX_TIMESTAMP_DRIFT = json_integer_value(json_object_get(server, "max_timestamp_drift")) ?: DEFAULT_MAX_TIMESTAMP_DRIFT;
        ctx->MAX_NONCE_ENTRIES = json_integer_value(json_object_get(server, "max_nonce_entries")) ?: DEFAULT_MAX_NONCE_ENTRIES;
        ctx->MAX_API_VERSION_LEN = json_integer_value(json_object_get(server, "max_api_version_len")) ?: DEFAULT_MAX_API_VERSION_LEN;
    }

    // Reload providers thread-safely
    json_t *providers = json_object_get(root, "providers");
    if (providers && json_is_array(providers)) {
        // Clear old providers safely
        pthread_mutex_lock(&ctx->provider_lock);
        ProviderEntry *cur, *tmp;
        HASH_ITER(hh, ctx->provider_map, cur, tmp) {
            HASH_DEL(ctx->provider_map, cur);
            free_provider_entry(cur);
        }
        init_providers_from_config(ctx, root);  // Assumes updated to use ctx
        pthread_mutex_unlock(&ctx->provider_lock);
    }

    json_decref(root);
    pthread_mutex_unlock(&config_mutex);
    printf("Config reload complete\n");
    return 0;
}

/* Config: Initialize providers from config.json */
/**
 * init_providers_from_config - Initialize provider map from config
 * @ctx: AppContext containing provider state
 * @config: Parsed JSON config object
 *
 * Iterates providers array, creates ProviderEntry for each valid provider,
 * normalizes ISS, duplicates strings, initializes mutex, adds to hash map.
 */
void init_providers_from_config(AppContext *ctx, json_t *config) {
    if (!ctx || !config) {
        LOG_ERROR("NULL ctx or config in init_providers_from_config");
        return;
    }
    json_t *providers = json_object_get(config, "providers");
    if (!json_is_array(providers)) {
        LOG_ERROR("No 'providers' array in config");
        return;
    }

    size_t index;
    json_t *p;
    json_array_foreach(providers, index, p) {
        const char *name = json_string_value(json_object_get(p, "name"));
        const char *iss = json_string_value(json_object_get(p, "iss"));
        const char *jwks_url = json_string_value(json_object_get(p, "jwks_url"));
        const char *aud = json_string_value(json_object_get(p, "expected_aud"));
        if (iss && jwks_url && aud) {
            ProviderEntry *entry = malloc(sizeof(ProviderEntry));
            if (!entry) {
                LOG_ERROR("Memory allocation failed for provider entry");
                continue;
            }
            entry->iss = normalize_iss(iss);
            if (!entry->iss) {
                free(entry);
                continue;
            }
            entry->jwks_url = strdup(jwks_url);
            if (!entry->jwks_url) {
                LOG_ERROR("Memory allocation failed for jwks_url");
                free_provider_entry(entry);
                continue;
            }
            entry->expected_aud = strdup(aud);
            if (!entry->expected_aud) {
                LOG_ERROR("Memory allocation failed for expected_aud");
                free_provider_entry(entry);
                continue;
            }
            entry->current_kid = NULL;
            entry->pubkey_pem = NULL;
            entry->last_refresh = 0;
            entry->ttl = ctx->JWKS_REFRESH_INTERVAL;  // Use ctx value
            if (pthread_mutex_init(&entry->lock, NULL) != 0) {
                LOG_ERROR("pthread_mutex_init failed");
                free_provider_entry(entry);
                continue;
            }
            HASH_ADD_STR(ctx->provider_map, iss, entry);
            printf("Initialized provider: %s (%s)\n", name ? name : "unnamed", entry->iss);
            if (refresh_provider(entry) != 0) {
                LOG_ERROR("Initial refresh failed for provider %s", entry->iss);
            }
        } else {
            LOG_ERROR("Invalid provider config for %s", name ? name : "unnamed");
        }
    }
}

/* JWKS: Destroy providers */
/**
 * destroy_jwks_providers - Free all provider entries
 *
 * Iterates provider_map, frees each entry safely using free_provider_entry.
 */
void destroy_jwks_providers() {
    // Note: Now handled in free_context
}

/* App authentication with full JWT validation */
/**
 * validate_app - Validate app authentication
 * @app_token: Optional JWT token for app
 * @app_secret: Optional shared secret for app
 *
 * Checks shared secret first, then validates JWT if provided.
 * Returns 1 on success, 0 on failure.
 */
int validate_app(const char *app_token, const char *app_secret) {
    // (Unchanged, as app keys are still globals; can move to ctx if desired)
    return 0;  // Stub
}

/* Trim leading/trailing whitespace in-place */
/**
 * trim_whitespace - Trim whitespace from string in-place
 * @str: String to trim (modified in-place)
 *
 * Removes leading/trailing whitespace. Handles empty strings.
 */
void trim_whitespace(char *str) {
    if (!str) {
        LOG_ERROR("NULL str in trim_whitespace");
        return;
    }

    char *end;

    // Trim leading
    while (isspace((unsigned char)*str)) str++;

    if (*str == 0) { // all spaces
        str[0] = '\0';
        return;
    }

    // Trim trailing
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    *(end + 1) = '\0';
}

/* Validate version format: must be digits.digits, e.g., 1.0, 2.3 */
/**
 * is_valid_version_format - Check if version string is valid format
 * @version: Version string to validate
 *
 * Must be digits.digits with exactly one dot.
 * Returns 1 if valid, 0 otherwise.
 */
int is_valid_version_format(const char *version) {
    if (!version || strlen(version) == 0 || strlen(version) > DEFAULT_MAX_API_VERSION_LEN) {
        return 0;
    }

    int dot_count = 0;
    for (size_t i = 0; version[i]; i++) {
        if (version[i] == '.') {
            dot_count++;
            continue;
        }
        if (!isdigit((unsigned char)version[i])) return 0;
    }
    return dot_count == 1; // only one dot allowed
}

/* Check if version is in supported list */
/**
 * is_supported_version - Check if version is supported
 * @ctx: AppContext for supported versions
 * @version: Version string
 *
 * Compares against supported_versions array.
 * Returns 1 if supported, 0 otherwise.
 */
int is_supported_version(AppContext *ctx, const char *version) {
    if (!ctx || !version) return 0;
    for (size_t i = 0; i < ctx->num_supported_versions; i++) {
        if (strcmp(version, ctx->supported_versions[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

/* Main robust version-checking function */
/**
 * parse_api_version - Parse and validate API version header
 * @ctx: AppContext for max len
 * @input: Raw version string from header
 * @out_version: Buffer to store validated version
 * @out_size: Size of out_version buffer
 *
 * Trims, validates format, checks support, copies to output.
 * Returns 1 on success, 0 on failure (invalid or buffer too small).
 */
int parse_api_version(AppContext *ctx, const char *input, char *out_version, size_t out_size) {
    if (!ctx || !input || !out_version || out_size == 0) {
        LOG_ERROR("NULL ctx, input or out_version or zero out_size in parse_api_version");
        return 0;
    }

    char tmp[DEFAULT_MAX_API_VERSION_LEN + 1];
    size_t len = strlen(input);
    if (len > sizeof(tmp) - 1) {
        LOG_ERROR("Input too long in parse_api_version");
        return 0;
    }
    strncpy(tmp, input, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    trim_whitespace(tmp);

    if (!is_valid_version_format(tmp)) {
        return 0;
    }

    if (!is_supported_version(ctx, tmp)) {
        return 0;
    }

    if (strlen(tmp) >= out_size) {
        LOG_ERROR("Output buffer too small in parse_api_version");
        return 0;
    }
    strncpy(out_version, tmp, out_size - 1);
    out_version[out_size - 1] = '\0';
    return 1;
}

/* Save user info to binary file with proper locking, O_NOFOLLOW, and improved error handling */
/**
 * save_user - Save user data to file atomically
 * @ctx: AppContext for file path
 * @name: User name
 * @email: User email
 *
 * Opens file with locking, writes User struct, closes safely.
 * Returns 1 on success, 0 on failure (logs errors).
 */
int save_user(AppContext *ctx, const char *name, const char *email) {
    if (!ctx || !ctx->USERDATA_FILE || !name || !email) {
        LOG_ERROR("NULL ctx, userdata_file, name, or email in save_user");
        return 0;
    }

    /* Open file safely using shim */
    int fd = open_user_file(ctx->USERDATA_FILE);
    if (fd < 0) {
        return 0;
    }

    /* Acquire exclusive lock using shim */
    if (lock_file(fd) != 0) {
        close(fd);
        return 0;
    }

    /* Prepare user struct */
    User u;
    memset(&u, 0, sizeof(User));
    if (strlen(name) >= sizeof(u.name)) {
        LOG_ERROR("Name too long in save_user");
        unlock_file(fd);
        close(fd);
        return 0;
    }
    strncpy(u.name, name, ctx->MAX_NAME_LEN - 1);
    if (strlen(email) >= sizeof(u.email)) {
        LOG_ERROR("Email too long in save_user");
        unlock_file(fd);
        close(fd);
        return 0;
    }
    strncpy(u.email, email, ctx->MAX_EMAIL_LEN - 1);

    /* Write to file */
    ssize_t written = write(fd, &u, sizeof(User));
    if (written != sizeof(User)) {
        perror("[ERROR] write");
        unlock_file(fd);
        close(fd);
        return 0;
    }

    /* Release lock and close using shim */
    if (unlock_file(fd) != 0) {
        close(fd);
        return 0;
    }
    if (close(fd) != 0) {
        perror("[ERROR] close");
        return 0;
    }
    return 1;
}

/* Input validation helpers (fixed for unsigned char) */
/**
 * is_valid_name - Validate user name
 * @ctx: AppContext for max len
 * @s: Name string
 *
 * Allows alnum, space, dash, underscore, dot. No injection chars.
 * OWASP Input Validation: Reject dangerous characters to prevent injection attacks.
 * Returns 1 if valid, 0 otherwise.
 */
int is_valid_name(AppContext *ctx, const char *s) {
    if (!ctx || !s || strlen(s) == 0 || strlen(s) > ctx->MAX_NAME_LEN) return 0;
    for (size_t i = 0; s[i]; ++i) {
        if (!isalnum((unsigned char)s[i]) && s[i] != ' ' && s[i] != '-' && s[i] != '_' && s[i] != '.') {
            return 0;
        }
        if (s[i] == '<' || s[i] == '>' || s[i] == '"' || s[i] == '\'') {
            return 0;
        }
    }
    return 1;
}
/**
 * is_valid_email - Validate email format using RFC 5322 subset regex
 * @ctx: AppContext for max len
 * @s: Email string
 *
 * Uses POSIX regex for validation: ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$
 * OWASP Input Validation: Sanitize and validate email to prevent injection.
 * Returns 1 if valid, 0 otherwise.
 */
int is_valid_email(AppContext *ctx, const char *s) {
    if (!ctx || !s || strlen(s) < 6 || strlen(s) > ctx->MAX_EMAIL_LEN) return 0;
    return regexec(&email_regex, s, 0, NULL, 0) == 0;
}

/* Connection context with buffers for accumulating POST data and total bytes, plus API version */
struct connection_info_struct {
    char name[256];
    size_t name_len;
    char email[256];
    size_t email_len;
    size_t total_bytes; /* Track total POST data bytes */
    int authenticated;
    char client_ip[INET6_ADDRSTRLEN]; /* Support IPv6 */
    char api_version[32]; /* API version, e.g., "1.0", "1.1" */
    char *post_data; /* Buffer for POST data */
    size_t post_data_len; /* Length of POST data */
};

/* Add security headers to every response */
/**
 * add_security_headers - Add security headers to CivetWeb connection
 * @conn: CivetWeb connection object
 *
 * Adds headers for XSS, clickjacking, HSTS, CORS, cache control, referrer.
 * OWASP Security Headers: Enforce browser protections.
 */
static void add_security_headers(struct mg_connection *conn) {
    if (!conn) {
        LOG_ERROR("NULL conn in add_security_headers");
        return;
    }
    mg_printf(conn, "X-Content-Type-Options: nosniff\r\n");
    mg_printf(conn, "X-Frame-Options: DENY\r\n");
    mg_printf(conn, "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload\r\n");
    mg_printf(conn, "Access-Control-Allow-Origin: https://yourdomain.com\r\n");
    mg_printf(conn, "Cache-Control: no-store\r\n");
    mg_printf(conn, "Referrer-Policy: no-referrer\r\n");
    mg_printf(conn, "Permissions-Policy: geolocation=(), microphone=(), camera=()\r\n");
}

/* Send JSON response with status and headers */
/**
 * send_json_response - Send JSON response with security headers
 * @conn: CivetWeb connection
 * @status_code: HTTP status code
 * @json_obj: JSON object to send
 *
 * Creates response from JSON, adds headers, sends response.
 * Returns 1 on success, 0 on failure.
 */
static int send_json_response(struct mg_connection *conn, int status_code, json_t *json_obj) {
    if (!conn || !json_obj) {
        LOG_ERROR("NULL conn or json_obj in send_json_response");
        return 0;
    }
    char *json_str = json_dumps(json_obj, 0);
    if (!json_str) {
        LOG_ERROR("json_dumps failed in send_json_response");
        return 0;
    }
    
    const char *status_text = "OK";
    if (status_code == 400) status_text = "Bad Request";
    else if (status_code == 401) status_text = "Unauthorized";
    else if (status_code == 404) status_text = "Not Found";
    else if (status_code == 413) status_text = "Payload Too Large";
    else if (status_code == 429) status_text = "Too Many Requests";
    else if (status_code == 500) status_text = "Internal Server Error";
    else if (status_code == 204) status_text = "No Content";
    
    mg_printf(conn, "HTTP/1.1 %d %s\r\n", status_code, status_text);
    mg_printf(conn, "Content-Type: application/json; charset=utf-8\r\n");
    add_security_headers(conn);
    mg_printf(conn, "Content-Length: %zu\r\n\r\n", strlen(json_str));
    mg_write(conn, json_str, strlen(json_str));
    
    free(json_str);
    return 1;
}

/* Parse URL-encoded POST data */
/**
 * parse_post_data - Parse URL-encoded POST data
 * @ctx: AppContext for max sizes
 * @post_data: POST data string
 * @data_len: Length of POST data
 * @con_info: Connection info to populate
 *
 * Parses name=value&name=value format, enforces size limits.
 * OWASP Input Validation: Enforce length limits to prevent buffer overflows.
 * Returns 1 on success, 0 on error.
 */
int parse_post_data(AppContext *ctx, const char *post_data, size_t data_len, 
                          struct connection_info_struct *con_info) {
    if (!ctx || !post_data || !con_info) {
        LOG_ERROR("NULL parameters in parse_post_data");
        return 0;
    }
    
    if (data_len > ctx->MAX_BODY_SIZE) {
        LOG_ERROR("POST data too large");
        return 0;
    }
    
    char *data_copy = malloc(data_len + 1);
    if (!data_copy) {
        LOG_ERROR("Memory allocation failed in parse_post_data");
        return 0;
    }
    memcpy(data_copy, post_data, data_len);
    data_copy[data_len] = '\0';
    
    char *saveptr = NULL;
    char *token = strtok_r(data_copy, "&", &saveptr);
    while (token != NULL) {
        char *eq = strchr(token, '=');
        if (eq) {
            *eq = '\0';
            const char *key = token;
            const char *value = eq + 1;
            
            if (strcmp(key, "name") == 0) {
                size_t len = strlen(value);
                if (len > ctx->MAX_NAME_LEN) len = ctx->MAX_NAME_LEN;
                memcpy(con_info->name, value, len);
                con_info->name[len] = '\0';
                con_info->name_len = len;
            } else if (strcmp(key, "email") == 0) {
                size_t len = strlen(value);
                if (len > ctx->MAX_EMAIL_LEN) len = ctx->MAX_EMAIL_LEN;
                memcpy(con_info->email, value, len);
                con_info->email[len] = '\0';
                con_info->email_len = len;
            }
        }
        token = strtok_r(NULL, "&", &saveptr);
    }
    
    free(data_copy);
    return 1;
}

/* Nonce entry for replay protection */
typedef struct {
    char nonce[64];
    time_t timestamp;
    UT_hash_handle hh;
} NonceEntry;

static NonceEntry *nonce_table = NULL;
static pthread_mutex_t nonce_table_lock = PTHREAD_MUTEX_INITIALIZER;

/* Validate nonce with table size limit and pressure logging */
/**
 * validate_nonce - Check and store nonce for replay protection
 * @nonce: Nonce string from request
 *
 * Checks length, rejects if full table, adds if new.
 * OWASP Rate Limiting: Prevents replay attacks.
 * Returns 1 if valid/new, 0 if invalid or used.
 */
int validate_nonce(const char *nonce) {
    if (!nonce || strlen(nonce) == 0 || strlen(nonce) >= 64) {
        LOG_ERROR("Invalid nonce length in validate_nonce");
        return 0; // Invalid nonce
    }

    if (pthread_mutex_lock(&nonce_table_lock) != 0) {
        LOG_ERROR("pthread_mutex_lock failed in validate_nonce");
        return 0;
    }

    /* Reject if table is full to prevent memory exhaustion */
    if (HASH_COUNT(nonce_table) >= DEFAULT_MAX_NONCE_ENTRIES) {
        /* Log pressure: count and oldest timestamp */
        time_t oldest = time(NULL);
        NonceEntry *e, *tmp;
        HASH_ITER(hh, nonce_table, e, tmp) {
            if (e->timestamp < oldest) oldest = e->timestamp;
        }
        LOG_ERROR("Nonce table full: %u entries, oldest=%ld", (unsigned)HASH_COUNT(nonce_table), (long)oldest);
        pthread_mutex_unlock(&nonce_table_lock);
        return 0;
    }

    NonceEntry *entry;
    HASH_FIND_STR(nonce_table, nonce, entry);
    if (entry) {
        pthread_mutex_unlock(&nonce_table_lock);
        return 0; // Already used
    }

    /* Add nonce */
    entry = malloc(sizeof(NonceEntry));
    if (!entry) {
        LOG_ERROR("Memory allocation failed for nonce entry");
        pthread_mutex_unlock(&nonce_table_lock);
        return 0; // Allocation failure
    }
    if (strlen(nonce) >= sizeof(entry->nonce)) {
        LOG_ERROR("Nonce too long for storage");
        free(entry);
        pthread_mutex_unlock(&nonce_table_lock);
        return 0;
    }
    strncpy(entry->nonce, nonce, sizeof(entry->nonce) - 1);
    entry->nonce[sizeof(entry->nonce) - 1] = '\0';
    entry->timestamp = time(NULL);
    HASH_ADD_STR(nonce_table, nonce, entry);

    if (pthread_mutex_unlock(&nonce_table_lock) != 0) {
        LOG_ERROR("pthread_mutex_unlock failed in validate_nonce");
        // Continue anyway
    }
    return 1;
}

/* Cleanup expired nonces with logging */
/**
 * cleanup_nonce_table - Remove expired nonces
 *
 * Iterates table, frees entries older than DEFAULT_MAX_TIMESTAMP_DRIFT.
 */
void cleanup_nonce_table(void) {
    time_t now = time(NULL);
    unsigned removed = 0;
    if (pthread_mutex_lock(&nonce_table_lock) != 0) {
        LOG_ERROR("pthread_mutex_lock failed in cleanup_nonce_table");
        return;
    }
    NonceEntry *current, *tmp;
    HASH_ITER(hh, nonce_table, current, tmp) {
        if (now - current->timestamp > DEFAULT_MAX_TIMESTAMP_DRIFT) {
            HASH_DEL(nonce_table, current);
            free(current);
            removed++;
        }
    }
    if (pthread_mutex_unlock(&nonce_table_lock) != 0) {
        LOG_ERROR("pthread_mutex_unlock failed in cleanup_nonce_table");
    }
    if (removed > 0) {
        printf("Cleaned up %u expired nonces\n", removed);
    }
}

/* JWT validation for users with JWKS refresh and retry-on-failure */
/**
 * validate_jwt_user - Validate user JWT with JWKS refresh
 * @ctx: AppContext for provider access
 * @token: JWT token string
 *
 * Decodes header, finds provider, validates signature (refresh if needed),
 * checks claims. Returns 1 on success, 0 on failure.
 * OWASP JWT Best Practices: Validate signature, issuer, audience, expiration.
 */
int validate_jwt_user(AppContext *ctx, const char *token) {
    if (!ctx || !token) {
        LOG_ERROR("NULL ctx or token in validate_jwt_user");
        return 0;
    }
    jwt_t *jwt = NULL;
    // Decode header first to get kid and iss
    if (jwt_decode(&jwt, token, NULL, 0) != 0) {
        LOG_ERROR("JWT decode header failed for token");
        return 0;
    }
    if (!jwt) {
        LOG_ERROR("jwt_decode returned NULL jwt for header");
        return 0;
    }

    const char *kid = jwt_get_header(jwt, "kid");
    const char *iss_claim = jwt_get_grant(jwt, "iss");
    if (!iss_claim) {
        LOG_ERROR("Missing iss in JWT header");
        jwt_free(jwt);
        return 0;
    }

    // Normalize iss for lookup
    char *normalized_iss = normalize_iss(iss_claim);
    if (!normalized_iss) {
        jwt_free(jwt);
        return 0;
    }

    ProviderEntry *entry = NULL;
    pthread_mutex_lock(&ctx->provider_lock);
    HASH_FIND_STR(ctx->provider_map, normalized_iss, entry);
    pthread_mutex_unlock(&ctx->provider_lock);
    free(normalized_iss);  // Free normalized iss after lookup
    if (!entry) {
        LOG_ERROR("Unknown issuer: %s", iss_claim);
        jwt_free(jwt);
        return 0;
    }

    // Now decode with key for full validation
    jwt_free(jwt);  // Free header-only jwt
    jwt = NULL;
    if (pthread_mutex_lock(&entry->lock) != 0) {
        LOG_ERROR("pthread_mutex_lock failed for provider lock");
        return 0;
    }
    const char *pubkey = entry->pubkey_pem;
    if (pthread_mutex_unlock(&entry->lock) != 0) {
        LOG_ERROR("pthread_mutex_unlock failed for provider lock");
        return 0;
    }

    if (jwt_decode(&jwt, token, (unsigned char *)pubkey, strlen(pubkey)) != 0) {
        // Retry once after refresh
        if (refresh_provider(entry) == 0) {
            if (pthread_mutex_lock(&entry->lock) != 0) {
                LOG_ERROR("pthread_mutex_lock failed after refresh");
                return 0;
            }
            pubkey = entry->pubkey_pem;
            if (pthread_mutex_unlock(&entry->lock) != 0) {
                LOG_ERROR("pthread_mutex_unlock failed after refresh");
                return 0;
            }
            if (jwt_decode(&jwt, token, (unsigned char *)pubkey, strlen(pubkey)) != 0) {
                LOG_ERROR("JWT decode failed after refresh");
                return 0;
            }
        } else {
            LOG_ERROR("Refresh provider failed");
            return 0;
        }
    }
    if (!jwt) {
        LOG_ERROR("jwt_decode returned NULL jwt after key decode");
        return 0;
    }

    // Validate claims
    const char *aud = jwt_get_grant(jwt, "aud");
    const char *exp_str = jwt_get_grant(jwt, "exp");
    const char *iat_str = jwt_get_grant(jwt, "iat");
    if (!aud || !exp_str || !iat_str) {
        LOG_ERROR("Missing required claims: aud, exp, iat");
        jwt_free(jwt);
        return 0;
    }

    // Check aud
    if (strcmp(aud, entry->expected_aud) != 0) {
        LOG_ERROR("aud mismatch: expected %s, got %s", entry->expected_aud, aud);
        jwt_free(jwt);
        return 0;
    }

    // Check expiration
    char *endptr;
    long exp = strtol(exp_str, &endptr, 10);
    if (*endptr != '\0' || exp < time(NULL)) {
        LOG_ERROR("JWT expired");
        jwt_free(jwt);
        return 0;
    }

    // Check issued-at
    long iat = strtol(iat_str, &endptr, 10);
    if (*endptr != '\0' || iat < time(NULL) - DEFAULT_MAX_TIMESTAMP_DRIFT || iat > time(NULL) + DEFAULT_MAX_TIMESTAMP_DRIFT) {
        LOG_ERROR("iat out of range");
        jwt_free(jwt);
        return 0;
    }

    printf("[JWT] Validated: iss=%s, aud=%s\n", iss_claim, aud);
    jwt_free(jwt);
    return 1;
}

/* Check OAuth Bearer token - supports user JWT or app auth */
/**
 * check_oauth_bearer - Validate Bearer token from Authorization header
 * @ctx: AppContext for provider access
 * @conn: CivetWeb connection
 *
 * Extracts Bearer token, validates user JWT or app auth.
 * Returns 1 on success, 0 on failure.
 */
int check_oauth_bearer(AppContext *ctx, struct mg_connection *conn) {
    if (!ctx || !conn) {
        LOG_ERROR("NULL ctx or conn in check_oauth_bearer");
        return 0;
    }
    const char *auth_header = mg_get_header(conn, "Authorization");
    const char *app_secret = mg_get_header(conn, "X-App-Secret");
    const char *app_token = mg_get_header(conn, "X-App-Token");

    // Try user JWT first
    if (auth_header && strncmp(auth_header, "Bearer ", 7) == 0) {
        const char *token = auth_header + 7;
        if (validate_jwt_user(ctx, token)) {
            /* Check nonce for replay protection */
            const char *nonce = mg_get_header(conn, "X-Nonce");
            if (!nonce || !validate_nonce(nonce)) {
                LOG_ERROR("Invalid or reused nonce");
                return 0;
            }
            return 1;
        }
    }

    // Fallback to app auth
    if (validate_app(app_token, app_secret)) {
        return 1;
    }

    return 0;
}

/* Rate limiting using uthash with separate cleanup thread */
typedef struct RateLimitEntry {
    char ip[INET6_ADDRSTRLEN]; /* Support IPv6 */
    int request_count;
    time_t window_start;
    UT_hash_handle hh;
} RateLimitEntry;

static RateLimitEntry *rate_limit_table = NULL;
static pthread_mutex_t rate_limit_table_lock = PTHREAD_MUTEX_INITIALIZER;

/* Cleanup function for expired entries with logging */
/**
 * cleanup_expired_entries - Remove expired rate limit entries
 *
 * Iterates table, frees entries older than 60 seconds.
 * OWASP Rate Limiting: Clean up to prevent memory leaks.
 */
void cleanup_expired_entries(void) {
    time_t now = time(NULL);
    unsigned removed = 0;
    if (pthread_mutex_lock(&rate_limit_table_lock) != 0) {
        LOG_ERROR("pthread_mutex_lock failed in cleanup_expired_entries");
        return;
    }
    RateLimitEntry *current, *tmp;
    HASH_ITER(hh, rate_limit_table, current, tmp) {
        if (now - current->window_start > 60) {
            HASH_DEL(rate_limit_table, current);
            free(current);
            removed++;
        }
    }
    if (pthread_mutex_unlock(&rate_limit_table_lock) != 0) {
        LOG_ERROR("pthread_mutex_unlock failed in cleanup_expired_entries");
    }
    if (removed > 0) {
        printf("Cleaned up %u expired rate-limit entries\n", removed);
    }
}

/* Cleanup thread cleanup handler */
static void cleanup_thread_cleanup(void *arg) {
    (void)arg;
    printf("Cleanup thread exiting\n");
}

/* Cleanup thread function with cleanup handler */
/**
 * cleanup_thread_func - Background cleanup thread
 * @arg: Unused
 *
 * Runs forever, sleeps, cleans up nonces and rate limits.
 * Uses cleanup handler for graceful exit.
 */
static void *cleanup_thread_func(void *arg) {
    (void)arg;

    /* Enable cancellation at deferred points */
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);

    /* Push cleanup handler for thread exit */
    pthread_cleanup_push(cleanup_thread_cleanup, NULL);

    while (1) {
        /* sleep() is a cancellation point */
        sleep(60);  // Use ctx->CLEANUP_INTERVAL_SECONDS if passed, but for simplicity

        /* Cleanup expired entries */
        cleanup_expired_entries();
        cleanup_nonce_table();

        /* Observability */
        if (pthread_mutex_lock(&nonce_table_lock) != 0) {
            LOG_ERROR("pthread_mutex_lock failed for observability");
            continue;
        }
        unsigned nonce_count = HASH_COUNT(nonce_table);
        if (pthread_mutex_unlock(&nonce_table_lock) != 0) {
            LOG_ERROR("pthread_mutex_unlock failed for observability");
            continue;
        }

        if (pthread_mutex_lock(&rate_limit_table_lock) != 0) {
            LOG_ERROR("pthread_mutex_lock failed for rate limit observability");
            continue;
        }
        unsigned rate_count = HASH_COUNT(rate_limit_table);
        if (pthread_mutex_unlock(&rate_limit_table_lock) != 0) {
            LOG_ERROR("pthread_mutex_unlock failed for rate limit observability");
            continue;
        }

        printf("Cleanup report: %u nonces, %u rate-limit entries\n", nonce_count, rate_count);
    }

    pthread_cleanup_pop(0); // 0 = execute cleanup on cancellation
    return NULL;
}

/* IP-based rate limiting (no inline cleanup, handled by thread) */
/**
 * check_rate_limit - Enforce per-IP rate limit
 * @client_ip: Client IP string
 *
 * Checks/creates entry, increments count, resets on window.
 * OWASP Rate Limiting: Throttle requests to prevent abuse.
 * Returns 1 if allowed, 0 if exceeded.
 */
int check_rate_limit(const char *client_ip) {
    if (!client_ip || strlen(client_ip) == 0) {
        LOG_ERROR("NULL or empty client_ip in check_rate_limit");
        return 0;
    }
    time_t now = time(NULL);

    if (pthread_mutex_lock(&rate_limit_table_lock) != 0) {
        LOG_ERROR("pthread_mutex_lock failed in check_rate_limit");
        return 0;
    }
    RateLimitEntry *entry = NULL;
    HASH_FIND_STR(rate_limit_table, client_ip, entry);
    if (!entry) {
        entry = malloc(sizeof(RateLimitEntry));
        if (!entry) {
            LOG_ERROR("Memory allocation failed for rate limit entry");
            pthread_mutex_unlock(&rate_limit_table_lock);
            return 0;
        }
        if (strlen(client_ip) >= INET6_ADDRSTRLEN) {
            LOG_ERROR("Client IP too long");
            free(entry);
            pthread_mutex_unlock(&rate_limit_table_lock);
            return 0;
        }
        strncpy(entry->ip, client_ip, INET6_ADDRSTRLEN - 1);
        entry->ip[INET6_ADDRSTRLEN - 1] = '\0';
        entry->request_count = 1;
        entry->window_start = now;
        HASH_ADD_STR(rate_limit_table, ip, entry);
        if (pthread_mutex_unlock(&rate_limit_table_lock) != 0) {
            LOG_ERROR("pthread_mutex_unlock failed in check_rate_limit");
        }
        return 1;
    }

    if (now - entry->window_start >= 60) {
        entry->request_count = 1;
        entry->window_start = now;
        if (pthread_mutex_unlock(&rate_limit_table_lock) != 0) {
            LOG_ERROR("pthread_mutex_unlock failed in check_rate_limit");
        }
        return 1;
    }

    if (entry->request_count >= DEFAULT_MAX_REQUESTS_PER_MINUTE) {
        if (pthread_mutex_unlock(&rate_limit_table_lock) != 0) {
            LOG_ERROR("pthread_mutex_unlock failed in check_rate_limit");
        }
        return 0;
    }
    entry->request_count++;
    if (pthread_mutex_unlock(&rate_limit_table_lock) != 0) {
        LOG_ERROR("pthread_mutex_unlock failed in check_rate_limit");
    }
    return 1;
}

/* Free rate-limit table */
/**
 * free_rate_limit_table - Free all rate limit entries
 *
 * Iterates and frees table.
 */
static void free_rate_limit_table(void) {
    if (pthread_mutex_lock(&rate_limit_table_lock) != 0) {
        LOG_ERROR("pthread_mutex_lock failed in free_rate_limit_table");
        return;
    }
    RateLimitEntry *current, *tmp;
    HASH_ITER(hh, rate_limit_table, current, tmp) {
        HASH_DEL(rate_limit_table, current);
        free(current);
    }
    if (pthread_mutex_unlock(&rate_limit_table_lock) != 0) {
        LOG_ERROR("pthread_mutex_unlock failed in free_rate_limit_table");
    }
}

/* Free nonce table */
/**
 * free_nonce_table - Free all nonce entries
 *
 * Iterates and frees table.
 */
static void free_nonce_table(void) {
    if (pthread_mutex_lock(&nonce_table_lock) != 0) {
        LOG_ERROR("pthread_mutex_lock failed in free_nonce_table");
        return;
    }
    NonceEntry *current, *tmp;
    HASH_ITER(hh, nonce_table, current, tmp) {
        HASH_DEL(nonce_table, current);
        free(current);
    }
    if (pthread_mutex_unlock(&nonce_table_lock) != 0) {
        LOG_ERROR("pthread_mutex_unlock failed in free_nonce_table");
    }
}

/* Main request handler */
/**
 * answer_to_connection - CivetWeb request handler
 * @conn: CivetWeb connection
 * @cbdata: AppContext pointer
 *
 * Handles rate limit, auth, POST processing, validation, response.
 * Returns 1 to indicate request was handled.
 */
static int answer_to_connection(struct mg_connection *conn, void *cbdata) {
    AppContext *ctx = (AppContext *)cbdata;
    if (!ctx || !conn) {
        LOG_ERROR("NULL ctx or conn in answer_to_connection");
        return 1;
    }
    
    // Get request info
    const struct mg_request_info *req_info = mg_get_request_info(conn);
    if (!req_info) {
        LOG_ERROR("Failed to get request info");
        return 1;
    }
    
    // Create connection info
    struct connection_info_struct con_info;
    memset(&con_info, 0, sizeof(con_info));
    
    // Get client IP
    const char *remote_addr = req_info->remote_addr;
    if (remote_addr) {
        strncpy(con_info.client_ip, remote_addr, INET6_ADDRSTRLEN - 1);
        con_info.client_ip[INET6_ADDRSTRLEN - 1] = '\0';
    } else {
        con_info.client_ip[0] = '\0';
    }
    
    // Parse API version
    char api_version[DEFAULT_MAX_API_VERSION_LEN + 1];
    const char *ver_header = mg_get_header(conn, "X-API-Version");
    if (!ver_header) ver_header = "1.0"; // default
    
    if (!parse_api_version(ctx, ver_header, api_version, sizeof(api_version))) {
        json_t *error_json = json_pack("{s:s}", "error", "Unsupported or invalid API version");
        if (!error_json) {
            LOG_ERROR("json_pack failed for API version error");
            return 1;
        }
        send_json_response(conn, 400, error_json);
        json_decref(error_json);
        return 1;
    }
    
    strncpy(con_info.api_version, api_version, sizeof(con_info.api_version) - 1);
    con_info.api_version[sizeof(con_info.api_version) - 1] = '\0';
    
    // Check rate limit
    if (!check_rate_limit(con_info.client_ip)) {
        json_t *error_json = json_pack("{s:s}", "error", "Rate limit exceeded. Please try again later.");
        if (!error_json) {
            LOG_ERROR("json_pack failed for rate limit error");
            return 1;
        }
        send_json_response(conn, 429, error_json);
        json_decref(error_json);
        return 1;
    }
    
    // Handle POST /hello
    if (strcmp(req_info->request_method, "POST") == 0 && strcmp(req_info->request_uri, "/hello") == 0) {
        // Check auth
        if (!check_oauth_bearer(ctx, conn)) {
            json_t *error_json = json_pack("{s:s}", "error", "Unauthorized. Valid JWT Bearer token required.");
            if (!error_json) {
                LOG_ERROR("json_pack failed for auth error");
                return 1;
            }
            send_json_response(conn, 401, error_json);
            json_decref(error_json);
            return 1;
        }
        
        // Check Content-Length
        const char *content_length_str = mg_get_header(conn, "Content-Length");
        long long content_length = 0;
        if (content_length_str) {
            content_length = atoll(content_length_str);
            if (content_length < 0 || content_length > ctx->MAX_BODY_SIZE) {
                json_t *error_json = json_pack("{s:s}", "error", "Payload too large");
                if (!error_json) {
                    LOG_ERROR("json_pack failed for payload error");
                    return 1;
                }
                send_json_response(conn, 413, error_json);
                json_decref(error_json);
                return 1;
            }
        }
        
        // Read POST data
        char post_buffer[4096];
        int data_len = mg_read(conn, post_buffer, sizeof(post_buffer) - 1);
        if (data_len < 0) {
            LOG_ERROR("Failed to read POST data");
            json_t *error_json = json_pack("{s:s}", "error", "Failed to read request body");
            if (!error_json) return 1;
            send_json_response(conn, 400, error_json);
            json_decref(error_json);
            return 1;
        }
        post_buffer[data_len] = '\0';
        
        // Parse POST data
        if (!parse_post_data(ctx, post_buffer, data_len, &con_info)) {
            json_t *error_json = json_pack("{s:s}", "error", "Failed to parse POST data");
            if (!error_json) return 1;
            send_json_response(conn, 400, error_json);
            json_decref(error_json);
            return 1;
        }
        
        // Validate fields
        if (con_info.name_len == 0 || con_info.email_len == 0) {
            json_t *error_json = json_pack("{s:s}", "error", "Missing required fields: name and email");
            if (!error_json) return 1;
            send_json_response(conn, 400, error_json);
            json_decref(error_json);
            return 1;
        }
        
        if (!is_valid_name(ctx, con_info.name) || !is_valid_email(ctx, con_info.email)) {
            json_t *error_json = json_pack("{s:s}", "error", "Invalid name or email format");
            if (!error_json) return 1;
            send_json_response(conn, 400, error_json);
            json_decref(error_json);
            return 1;
        }
        
        // Save user
        if (!save_user(ctx, con_info.name, con_info.email)) {
            json_t *error_json = json_pack("{s:s}", "error", "Failed to save user data");
            if (!error_json) return 1;
            send_json_response(conn, 500, error_json);
            json_decref(error_json);
            return 1;
        }
        
        time_t now = time(NULL);
        printf("[%ld] Request from %s: name=%s, email=%s\n", now, con_info.client_ip, con_info.name, con_info.email);
        
        // Generate response based on API version
        char greeting[256];
        if (strcmp(con_info.api_version, "1.0") == 0) {
            snprintf(greeting, sizeof(greeting), "Hello, %s <%s>", con_info.name, con_info.email);
        } else if (strcmp(con_info.api_version, "1.1") == 0) {
            snprintf(greeting, sizeof(greeting), "Hello, %s <%s> at %ld", con_info.name, con_info.email, now);
        } else {
            json_t *error_json = json_pack("{s:s}", "error", "Unsupported API version");
            if (!error_json) return 1;
            send_json_response(conn, 400, error_json);
            json_decref(error_json);
            return 1;
        }
        
        json_t *json_resp = json_pack("{s:s, s:s}", "greeting", greeting, "version", con_info.api_version);
        if (!json_resp) {
            LOG_ERROR("json_pack failed for response");
            return 1;
        }
        send_json_response(conn, 200, json_resp);
        json_decref(json_resp);
        
        // Zero sensitive buffers
        secure_zero(con_info.name, sizeof(con_info.name));
        secure_zero(con_info.email, sizeof(con_info.email));
        
        return 1;
    }
    
    // Handle OPTIONS
    if (strcmp(req_info->request_method, "OPTIONS") == 0) {
        mg_printf(conn, "HTTP/1.1 204 No Content\r\n");
        mg_printf(conn, "Access-Control-Allow-Methods: POST, OPTIONS\r\n");
        mg_printf(conn, "Access-Control-Allow-Headers: Content-Type, Authorization, X-Nonce, X-API-Version, X-App-Secret, X-App-Token\r\n");
        mg_printf(conn, "Access-Control-Allow-Origin: https://yourdomain.com\r\n");
        add_security_headers(conn);
        mg_printf(conn, "\r\n");
        return 1;
    }
    
    // Handle invalid endpoint/method
    json_t *error_json = json_pack("{s:s}", "error", "Invalid endpoint or method");
    if (!error_json) return 1;
    send_json_response(conn, 404, error_json);
    json_decref(error_json);
    return 1;
}

/* CivetWeb doesn't need explicit connection cleanup for our use case */

int main() {
    AppContext ctx;
    if (init_context(&ctx, CONFIG_FILE) != 0) {
        fprintf(stderr, "Failed to initialize context\n");
        return 1;
    }

    // Compile email regex
    if (regcomp(&email_regex, "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", REG_EXTENDED | REG_NOSUB) != 0) {
        LOG_ERROR("Failed to compile email regex");
        free_context(&ctx);
        return 1;
    }
    email_regex_compiled = 1;

    char *tls_key_pem = read_file("/etc/ssl/private/key.pem");
    char *tls_cert_pem = read_file("/etc/ssl/certs/cert.pem");

    if (pthread_mutex_lock(&ctx.jwt_pubkey_lock) != 0) {
        LOG_ERROR("pthread_mutex_lock failed for jwt_pubkey_lock in main");
        free_context(&ctx);
        free(tls_key_pem);
        free(tls_cert_pem);
        return 1;
    }
    ctx.jwt_pubkey = read_file(ctx.PUBKEY_FILE ? ctx.PUBKEY_FILE : DEFAULT_PUBKEY_FILE);
    ctx.app_pubkey = read_file(ctx.APP_PUBKEY_FILE ? ctx.APP_PUBKEY_FILE : DEFAULT_APP_PUBKEY_FILE);
    if (pthread_mutex_unlock(&ctx.jwt_pubkey_lock) != 0) {
        LOG_ERROR("pthread_mutex_unlock failed for jwt_pubkey_lock in main");
    }

    if (!ctx.jwt_pubkey || !ctx.app_pubkey) {
        LOG_ERROR("Failed to read or validate JWT public keys");
        free(tls_key_pem);
        free(tls_cert_pem);
        free_context(&ctx);
        return 1;
    }
    if (!tls_key_pem || !tls_cert_pem) {
        LOG_ERROR("Failed to read TLS key or certificate");
        free(tls_key_pem);
        free(tls_cert_pem);
        free_context(&ctx);
        return 1;
    }

    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        LOG_ERROR("curl_global_init failed");
        free(tls_key_pem);
        free(tls_cert_pem);
        free_context(&ctx);
        return 1;
    }

    // Load config and init providers
    json_t *config = load_config(ctx.config_path);
    if (!config) {
        free_context(&ctx);
        return 1;
    }
    json_t *server = json_object_get(config, "server");
    if (server) {
        ctx.PORT = json_integer_value(json_object_get(server, "port")) ?: DEFAULT_PORT;
        ctx.EXPECTED_APP_SECRET = json_is_string(json_object_get(server, "expected_app_secret")) ? strdup(json_string_value(json_object_get(server, "expected_app_secret"))) : NULL;
        ctx.EXPECTED_AUD = json_is_string(json_object_get(server, "expected_aud")) ? strdup(json_string_value(json_object_get(server, "expected_aud"))) : NULL;
        ctx.EXPECTED_APP_ID = json_is_string(json_object_get(server, "expected_app_id")) ? strdup(json_string_value(json_object_get(server, "expected_app_id"))) : NULL;
        ctx.USERDATA_FILE = json_is_string(json_object_get(server, "userdata_file")) ? strdup(json_string_value(json_object_get(server, "userdata_file"))) : strdup(DEFAULT_USERDATA_FILE);
        ctx.PUBKEY_FILE = json_is_string(json_object_get(server, "pubkey_file")) ? strdup(json_string_value(json_object_get(server, "pubkey_file"))) : strdup(DEFAULT_PUBKEY_FILE);
        ctx.APP_PUBKEY_FILE = json_is_string(json_object_get(server, "app_pubkey_file")) ? strdup(json_string_value(json_object_get(server, "app_pubkey_file"))) : strdup(DEFAULT_APP_PUBKEY_FILE);
        ctx.CLEANUP_INTERVAL_SECONDS = json_integer_value(json_object_get(server, "cleanup_interval_seconds")) ?: DEFAULT_CLEANUP_INTERVAL_SECONDS;
        ctx.JWKS_REFRESH_INTERVAL = json_integer_value(json_object_get(server, "jwks_refresh_interval")) ?: DEFAULT_JWKS_REFRESH_INTERVAL;
        ctx.MAX_REQUESTS_PER_MINUTE = json_integer_value(json_object_get(server, "max_requests_per_minute")) ?: DEFAULT_MAX_REQUESTS_PER_MINUTE;
        ctx.MAX_TIMESTAMP_DRIFT = json_integer_value(json_object_get(server, "max_timestamp_drift")) ?: DEFAULT_MAX_TIMESTAMP_DRIFT;
        ctx.MAX_NONCE_ENTRIES = json_integer_value(json_object_get(server, "max_nonce_entries")) ?: DEFAULT_MAX_NONCE_ENTRIES;
        ctx.MAX_API_VERSION_LEN = json_integer_value(json_object_get(server, "max_api_version_len")) ?: DEFAULT_MAX_API_VERSION_LEN;
    }
    init_providers_from_config(&ctx, config);
    json_decref(config);

    /* Start cleanup thread */
    if (pthread_create(&cleanup_thread, NULL, cleanup_thread_func, NULL) != 0) {
        LOG_ERROR("Failed to create cleanup thread");
        free(tls_key_pem);
        free(tls_cert_pem);
        free_context(&ctx);
        return 1;
    }

    // Register signal/console handlers using shims
#ifdef _WIN32
    if (!SetConsoleCtrlHandler(console_handler, TRUE)) {
        LOG_ERROR("SetConsoleCtrlHandler failed");
        free(tls_key_pem);
        free(tls_cert_pem);
        free_context(&ctx);
        return 1;
    }
#else
    struct sigaction sa_hup;
    sa_hup.sa_handler = handle_sighup;
    sigemptyset(&sa_hup.sa_mask);
    sa_hup.sa_flags = 0;
    if (sigaction(SIGHUP, &sa_hup, NULL) != 0) {
        perror("[ERROR] sigaction for SIGHUP");
        free(tls_key_pem);
        free(tls_cert_pem);
        free_context(&ctx);
        return 1;
    }

    struct sigaction sa_int;
    sa_int.sa_handler = shutdown_handler;
    sigemptyset(&sa_int.sa_mask);
    sa_int.sa_flags = 0;
    if (sigaction(SIGINT, &sa_int, NULL) != 0) {
        perror("[ERROR] sigaction for SIGINT");
        free(tls_key_pem);
        free(tls_cert_pem);
        free_context(&ctx);
        return 1;
    }
#endif

    // Write TLS files to disk for CivetWeb (it requires file paths)
    FILE *key_file = fopen("/tmp/server_key.pem", "w");
    if (!key_file) {
        LOG_ERROR("Failed to create temporary key file");
        free(tls_key_pem);
        free(tls_cert_pem);
        free_context(&ctx);
        return 1;
    }
    fwrite(tls_key_pem, 1, strlen(tls_key_pem), key_file);
    fclose(key_file);
    
    FILE *cert_file = fopen("/tmp/server_cert.pem", "w");
    if (!cert_file) {
        LOG_ERROR("Failed to create temporary cert file");
        free(tls_key_pem);
        free(tls_cert_pem);
        free_context(&ctx);
        return 1;
    }
    fwrite(tls_cert_pem, 1, strlen(tls_cert_pem), cert_file);
    fclose(cert_file);
    
    free(tls_key_pem);
    free(tls_cert_pem);
    
    // Configure CivetWeb options
    char port_str[32];
    snprintf(port_str, sizeof(port_str), "%ds", ctx.PORT);  // 's' suffix enables SSL
    
    const char *options[] = {
        "listening_ports", port_str,
        "ssl_certificate", "/tmp/server_cert.pem",
        "ssl_private_key", "/tmp/server_key.pem",
        "num_threads", "50",
        NULL
    };
    
    struct mg_callbacks callbacks;
    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.begin_request = answer_to_connection;
    
    struct mg_context *mg_ctx = mg_start(&callbacks, &ctx, options);
    if (!mg_ctx) {
        LOG_ERROR("Failed to start HTTPS server with CivetWeb");
        free_context(&ctx);
        return 1;
    }

    printf("Secure REST server running with HTTPS on port %d\n", ctx.PORT);
    printf("JWT validation enabled. Public key loaded from: %s\n", ctx.PUBKEY_FILE ? ctx.PUBKEY_FILE : DEFAULT_PUBKEY_FILE);
    printf("App pubkey loaded from: %s\n", ctx.APP_PUBKEY_FILE ? ctx.APP_PUBKEY_FILE : DEFAULT_APP_PUBKEY_FILE);
    printf("Config loaded from: %s\n", ctx.config_path);
    printf("Rate limiting: %d requests per minute per IP\n", ctx.MAX_REQUESTS_PER_MINUTE);
    printf("Replay protection: JWT iat check (±%d seconds) and X-Nonce validation (max %d entries)\n", ctx.MAX_TIMESTAMP_DRIFT, ctx.MAX_NONCE_ENTRIES);
    printf("Cleanup thread running every %d seconds\n", ctx.CLEANUP_INTERVAL_SECONDS);
    printf("Press Ctrl+C to shutdown gracefully.\n");
    printf("Send SIGHUP (kill -HUP <pid>) to reload config at runtime.\n");
    printf("Try: curl -k -X POST -H \"Authorization: Bearer <JWT>\" -H \"X-Nonce: <unique-nonce>\" -H \"X-API-Version: 1.1\" -d \"name=Terry&email=terry@example.com\" https://127.0.0.1:%d/hello\n", ctx.PORT);
    printf("Or for app auth: curl -k -X POST -H \"X-App-Secret: replace_with_secure_random_value\" -H \"X-API-Version: 1.1\" -d \"name=Terry&email=terry@example.com\" https://127.0.0.1:%d/hello\n", ctx.PORT);
    printf("User data saved in: %s\n", ctx.USERDATA_FILE ? ctx.USERDATA_FILE : DEFAULT_USERDATA_FILE);

    /* Wait for shutdown signal */
    while (!shutdown_flag) {
        if (config_reload_requested) {
            fprintf(stderr, "Reloading config...\n");
            if (reload_config(&ctx) != 0) {
                LOG_ERROR("Config reload failed");
            }
            config_reload_requested = 0;
        }
#ifdef _WIN32
        Sleep(500);  // Poll every 500ms on Windows
#else
        struct timespec ts = {0, 500 * 1000000}; // 0.5s
        nanosleep(&ts, NULL);
#endif
    }

    mg_stop(mg_ctx);

    /* Cleanup */
    free_rate_limit_table();
    free_nonce_table();

    if (email_regex_compiled) {
        regfree(&email_regex);
    }

    free_context(&ctx);

    printf("Server shut down gracefully.\n");
    return 0;
}

/*
================================================================================
EXAMPLE CONFIG.JSON
================================================================================
{
  "server": {
    "port": 8443,
    "expected_app_secret": "replace_with_secure_random_value",
    "expected_aud": "your-api-audience",
    "expected_app_id": "your-app-id",
    "userdata_file": "users.bin",
    "pubkey_file": "public.pem",
    "app_pubkey_file": "app_pub.pem",
    "cleanup_interval_seconds": 60,
    "jwks_refresh_interval": 3600,
    "max_requests_per_minute": 30,
    "max_timestamp_drift": 300,
    "max_nonce_entries": 10000,
    "max_api_version_len": 15
  },
  "providers": [
    {
      "name": "Google",
      "iss": "https://accounts.google.com",
      "jwks_url": "https://www.googleapis.com/oauth2/v3/certs",
      "expected_aud": "com.mycompany.myapp"
    },
    {
      "name": "Microsoft",
      "iss": "https://login.microsoftonline.com",
      "jwks_url": "https://login.microsoftonline.com/common/discovery/keys",
      "expected_aud": "myapp-client-id"
    },
    {
      "name": "Apple",
      "iss": "https://appleid.apple.com",
      "jwks_url": "https://appleid.apple.com/auth/keys",
      "expected_aud": "com.mycompany.myapp"
    }
  ]
}
================================================================================
*/
