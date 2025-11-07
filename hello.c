/*
================================================================================
SECURE REST SERVER: UNIFIED MEGA-TEMPLATE (CROSS-PLATFORM) - VERSION 38
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

Data Flow Overview (ASCII Diagram):
Client Request -> HTTPS Daemon -> Rate Limit Check -> Auth (JWT/App) -> API Version Parse -> POST Data Process -> Input Validation -> Save User -> JSON Response
     |                |             |                      |                   |                      |                        |
     v                v             v                      v                   v                      v                        v
  TLS Termination  MHD Handler   IP Table               JWKS Refresh       Version Support       Field Limits          File I/O               Error JSON

Security References:
- OWASP JWT Best Practices: https://tools.ietf.org/html/rfc8725 (Token validation, audience checks, expiration)
- OWASP Input Validation Cheat Sheet: https://owasp.org/www-project-cheat-sheets/cheatsheets/Input_Validation_Cheat_Sheet.html (Length limits, character restrictions)
- OWASP Rate Limiting: https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks (Per-IP rate limiting)
- OWASP Transport Layer Protection: https://owasp.org/www-project-cheat-sheets/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html (HTTPS enforcement, HSTS)
- CWE-20: Improper Input Validation (Addressed via length checks, type validation, and sanitization)
- CWE-287: Improper Authentication (Addressed via JWT signature verification, nonce replay protection)

Build commands (recommended for 64-bit for better performance):
  Linux:   gcc -o server server.c -lcurl -lssl -lcrypto -ljansson -pthread
  macOS:   clang -o server server.c -lcurl -lssl -lcrypto -ljansson
  Windows: cl server.c /link ws2_32.lib User32.lib Advapi32.lib Crypt32.lib
           (For MinGW-w64: x86_64-w64-mingw32-gcc server.c -o server.exe -lcurl -lssl -lcrypto -ljansson -pthread)

Run with: ./server (config.json in same dir)
Reload: kill -HUP <pid> (POSIX) or Ctrl+Break (Windows simulation)

Config example in file comments below.
================================================================================
*/

#include <microhttpd.h>
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
#include <windows.h>
#include <io.h>
#endif

/* uthash for dynamic hash map */
#include "uthash.h"

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

/* Config-loaded globals */
static int PORT;
static char *EXPECTED_APP_SECRET;
static char *EXPECTED_AUD;
static char *EXPECTED_APP_ID;
static char *USERDATA_FILE;
static char *PUBKEY_FILE;
static char *APP_PUBKEY_FILE;
static int CLEANUP_INTERVAL_SECONDS;
static time_t JWKS_REFRESH_INTERVAL;
static int MAX_REQUESTS_PER_MINUTE;
static int MAX_TIMESTAMP_DRIFT;
static int MAX_NONCE_ENTRIES;
static int MAX_API_VERSION_LEN;
static int MAX_NAME_LEN = 48;  /* Fixed, not configurable */
static int MAX_EMAIL_LEN = 96; /* Fixed, not configurable */
static int MAX_BODY_SIZE = 4096; /* Fixed, not configurable */

/* List of supported versions */
static const char *supported_versions[] = { "1.0", "1.1" };
static const size_t num_supported_versions = sizeof(supported_versions)/sizeof(supported_versions[0]);

/* Thread-safe JWT public keys access */
static char *jwt_pubkey = NULL;
static char *app_pubkey = NULL;
static pthread_mutex_t jwt_pubkey_lock = PTHREAD_MUTEX_INITIALIZER;

/* Email validation regex */
static regex_t email_regex;
static int email_regex_compiled = 0;

/* Updated ProviderEntry for JWKS caching */
typedef struct {
    const char *iss;          // issuer identifier (normalized)
    const char *jwks_url;     // JWKS endpoint URL
    const char *expected_aud; // expected audience for validation
    char *current_kid;        // current key ID from JWKS
    char *pubkey_pem;         // cached PEM public key
    time_t last_refresh;      // last refresh timestamp
    time_t ttl;               // time-to-live for cache
    pthread_mutex_t lock;     // thread-safe updates
    UT_hash_handle hh;
} ProviderEntry;

static ProviderEntry *provider_map = NULL;

/* Cleanup thread */
static pthread_t cleanup_thread;

/* Shutdown flag */
static volatile sig_atomic_t shutdown_flag = 0;

/* Config reload globals */
static pthread_mutex_t config_mutex = PTHREAD_MUTEX_INITIALIZER;
static volatile sig_atomic_t config_reload_requested = 0;

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
    free((char *)entry->iss);
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
int is_supported_version(const char *version);
int parse_api_version(const char *input, char *out_version, size_t out_size);
int save_user(const char *filename, const char *name, const char *email);
int is_valid_name(const char *s);
int is_valid_email(const char *s);
int validate_nonce(const char *nonce);
void cleanup_nonce_table(void);
int validate_jwt_user(const char *token);
int check_oauth_bearer(struct MHD_Connection *connection);
int check_rate_limit(const char *client_ip);
void cleanup_expired_entries(void);

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
    while (len > 0 && (isspace((unsigned char)raw[len - 1]) || raw[len - 1] == '/')) len--;
    size_t start = 0;
    while (start < len && isspace((unsigned char)raw[start])) start++;
    size_t new_len = len - start;
    char *out = malloc(new_len + 1);
    if (!out) {
        free(normalized);
        LOG_ERROR("Memory allocation failed for out in normalize_iss");
        return NULL;
    }
    memcpy(out, raw + start, new_len);
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

/* Helper: Decode base64url to binary (improved with BIO_ctrl_pending) */
/**
 * base64url_decode - Decode base64url string to binary data
 * @in: Input base64url string
 * @out: Output buffer (malloc'ed by function)
 * @out_len: Length of decoded data
 *
 * Converts base64url to standard base64, decodes using OpenSSL BIO.
 * Returns 0 on success, non-zero on error.
 * Caller must free *out on success.
 */
static int base64url_decode(const char *in, unsigned char **out, size_t *out_len) {
    if (!in || !out || !out_len) {
        LOG_ERROR("NULL parameters in base64url_decode");
        return 0;
    }
    BIO *bio, *b64;
    char *in_copy = strdup(in);
    if (!in_copy) {
        LOG_ERROR("Memory allocation failed for in_copy in base64url_decode");
        return 0;
    }
    size_t in_len = strlen(in_copy);

    // Replace base64url chars with standard base64
    for (size_t i = 0; i < in_len; i++) {
        if (in_copy[i] == '-') in_copy[i] = '+';
        else if (in_copy[i] == '_') in_copy[i] = '/';
    }

    // Add padding if needed
    size_t padding = in_len % 4;
    if (padding) {
        in_copy = realloc(in_copy, in_len + 4 - padding + 1);
        if (!in_copy) {
            LOG_ERROR("Memory reallocation failed for padding in base64url_decode");
            return 0;
        }
        for (size_t i = 0; i < 4 - padding; i++) {
            in_copy[in_len + i] = '=';
        }
        in_copy[in_len + (4 - padding)] = '\0';
    }

    bio = BIO_new_mem_buf(in_copy, -1);
    if (!bio) {
        LOG_ERROR("BIO_new_mem_buf failed in base64url_decode");
        free(in_copy);
        return 0;
    }
    b64 = BIO_new(BIO_f_base64());
    if (!b64) {
        LOG_ERROR("BIO_new for base64 failed in base64url_decode");
        BIO_free(bio);
        free(in_copy);
        return 0;
    }
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    *out_len = BIO_ctrl_pending(bio);  // Use BIO_ctrl_pending for accurate length
    *out = malloc(*out_len);
    if (!*out) {
        LOG_ERROR("Memory allocation failed for out in base64url_decode");
        BIO_free_all(bio);
        free(in_copy);
        return 0;
    }
    int decodeLen = BIO_read(bio, *out, *out_len);
    if (decodeLen <= 0) {
        LOG_ERROR("BIO_read failed in base64url_decode");
        free(*out);
        *out = NULL;
        BIO_free_all(bio);
        free(in_copy);
        return 0;
    }

    BIO_free_all(bio);
    free(in_copy);
    return decodeLen;
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
    if (curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, [](char *ptr, size_t size, size_t nmemb, void *userdata) -> size_t {
        if (!ptr || !userdata) return 0;
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
    }) != CURLE_OK) {
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

    // Load server settings
    json_t *server = json_object_get(root, "server");
    if (server) {
        PORT = json_integer_value(json_object_get(server, "port")) ?: DEFAULT_PORT;
        EXPECTED_APP_SECRET = json_is_string(json_object_get(server, "expected_app_secret")) ? strdup(json_string_value(json_object_get(server, "expected_app_secret"))) : NULL;
        if (json_is_string(json_object_get(server, "expected_app_secret")) && !EXPECTED_APP_SECRET) {
            LOG_ERROR("Memory allocation failed for EXPECTED_APP_SECRET");
            json_decref(root);
            return NULL;
        }
        EXPECTED_AUD = json_is_string(json_object_get(server, "expected_aud")) ? strdup(json_string_value(json_object_get(server, "expected_aud"))) : NULL;
        if (json_is_string(json_object_get(server, "expected_aud")) && !EXPECTED_AUD) {
            LOG_ERROR("Memory allocation failed for EXPECTED_AUD");
            free(EXPECTED_APP_SECRET);
            json_decref(root);
            return NULL;
        }
        EXPECTED_APP_ID = json_is_string(json_object_get(server, "expected_app_id")) ? strdup(json_string_value(json_object_get(server, "expected_app_id"))) : NULL;
        if (json_is_string(json_object_get(server, "expected_app_id")) && !EXPECTED_APP_ID) {
            LOG_ERROR("Memory allocation failed for EXPECTED_APP_ID");
            free(EXPECTED_APP_SECRET);
            free(EXPECTED_AUD);
            json_decref(root);
            return NULL;
        }
        USERDATA_FILE = json_is_string(json_object_get(server, "userdata_file")) ? strdup(json_string_value(json_object_get(server, "userdata_file"))) : strdup(DEFAULT_USERDATA_FILE);
        if (!USERDATA_FILE) {
            LOG_ERROR("Memory allocation failed for USERDATA_FILE");
            free(EXPECTED_APP_SECRET);
            free(EXPECTED_AUD);
            free(EXPECTED_APP_ID);
            json_decref(root);
            return NULL;
        }
        PUBKEY_FILE = json_is_string(json_object_get(server, "pubkey_file")) ? strdup(json_string_value(json_object_get(server, "pubkey_file"))) : strdup(DEFAULT_PUBKEY_FILE);
        if (!PUBKEY_FILE) {
            LOG_ERROR("Memory allocation failed for PUBKEY_FILE");
            free(EXPECTED_APP_SECRET);
            free(EXPECTED_AUD);
            free(EXPECTED_APP_ID);
            free(USERDATA_FILE);
            json_decref(root);
            return NULL;
        }
        APP_PUBKEY_FILE = json_is_string(json_object_get(server, "app_pubkey_file")) ? strdup(json_string_value(json_object_get(server, "app_pubkey_file"))) : strdup(DEFAULT_APP_PUBKEY_FILE);
        if (!APP_PUBKEY_FILE) {
            LOG_ERROR("Memory allocation failed for APP_PUBKEY_FILE");
            free(EXPECTED_APP_SECRET);
            free(EXPECTED_AUD);
            free(EXPECTED_APP_ID);
            free(USERDATA_FILE);
            free(PUBKEY_FILE);
            json_decref(root);
            return NULL;
        }
        CLEANUP_INTERVAL_SECONDS = json_integer_value(json_object_get(server, "cleanup_interval_seconds")) ?: DEFAULT_CLEANUP_INTERVAL_SECONDS;
        JWKS_REFRESH_INTERVAL = json_integer_value(json_object_get(server, "jwks_refresh_interval")) ?: DEFAULT_JWKS_REFRESH_INTERVAL;
        MAX_REQUESTS_PER_MINUTE = json_integer_value(json_object_get(server, "max_requests_per_minute")) ?: DEFAULT_MAX_REQUESTS_PER_MINUTE;
        MAX_TIMESTAMP_DRIFT = json_integer_value(json_object_get(server, "max_timestamp_drift")) ?: DEFAULT_MAX_TIMESTAMP_DRIFT;
        MAX_NONCE_ENTRIES = json_integer_value(json_object_get(server, "max_nonce_entries")) ?: DEFAULT_MAX_NONCE_ENTRIES;
        MAX_API_VERSION_LEN = json_integer_value(json_object_get(server, "max_api_version_len")) ?: DEFAULT_MAX_API_VERSION_LEN;
    } else {
        // Use defaults if server section missing
        PORT = DEFAULT_PORT;
        EXPECTED_APP_SECRET = NULL;
        EXPECTED_AUD = NULL;
        EXPECTED_APP_ID = NULL;
        USERDATA_FILE = strdup(DEFAULT_USERDATA_FILE);
        if (!USERDATA_FILE) {
            LOG_ERROR("Memory allocation failed for default USERDATA_FILE");
            json_decref(root);
            return NULL;
        }
        PUBKEY_FILE = strdup(DEFAULT_PUBKEY_FILE);
        if (!PUBKEY_FILE) {
            LOG_ERROR("Memory allocation failed for default PUBKEY_FILE");
            free(USERDATA_FILE);
            json_decref(root);
            return NULL;
        }
        APP_PUBKEY_FILE = strdup(DEFAULT_APP_PUBKEY_FILE);
        if (!APP_PUBKEY_FILE) {
            LOG_ERROR("Memory allocation failed for default APP_PUBKEY_FILE");
            free(USERDATA_FILE);
            free(PUBKEY_FILE);
            json_decref(root);
            return NULL;
        }
        CLEANUP_INTERVAL_SECONDS = DEFAULT_CLEANUP_INTERVAL_SECONDS;
        JWKS_REFRESH_INTERVAL = DEFAULT_JWKS_REFRESH_INTERVAL;
        MAX_REQUESTS_PER_MINUTE = DEFAULT_MAX_REQUESTS_PER_MINUTE;
        MAX_TIMESTAMP_DRIFT = DEFAULT_MAX_TIMESTAMP_DRIFT;
        MAX_NONCE_ENTRIES = DEFAULT_MAX_NONCE_ENTRIES;
        MAX_API_VERSION_LEN = DEFAULT_MAX_API_VERSION_LEN;
    }

    return root;
}

/* Config: Reload config.json dynamically */
/**
 * reload_config - Reload config without restarting server
 * @path: Path to config file
 *
 * Locks config, loads new config, updates globals, clears old providers,
 * loads new providers. Returns 0 on success, -1 on error.
 */
int reload_config(const char *path) {
    if (!path) {
        LOG_ERROR("NULL path in reload_config");
        return -1;
    }
    pthread_mutex_lock(&config_mutex);

    json_t *root = load_config(path);
    if (!root) {
        pthread_mutex_unlock(&config_mutex);
        return -1;
    }

    // Reload server settings (same as initial load)
    json_t *server = json_object_get(root, "server");
    if (server) {
        int new_port = json_integer_value(json_object_get(server, "port")) ?: DEFAULT_PORT;
        char *new_secret = json_is_string(json_object_get(server, "expected_app_secret")) ? strdup(json_string_value(json_object_get(server, "expected_app_secret"))) : NULL;
        if (json_is_string(json_object_get(server, "expected_app_secret")) && !new_secret) {
            LOG_ERROR("Memory allocation failed for new_secret in reload_config");
            json_decref(root);
            pthread_mutex_unlock(&config_mutex);
            return -1;
        }
        char *new_aud = json_is_string(json_object_get(server, "expected_aud")) ? strdup(json_string_value(json_object_get(server, "expected_aud"))) : NULL;
        if (json_is_string(json_object_get(server, "expected_aud")) && !new_aud) {
            LOG_ERROR("Memory allocation failed for new_aud in reload_config");
            free(new_secret);
            json_decref(root);
            pthread_mutex_unlock(&config_mutex);
            return -1;
        }
        char *new_app_id = json_is_string(json_object_get(server, "expected_app_id")) ? strdup(json_string_value(json_object_get(server, "expected_app_id"))) : NULL;
        if (json_is_string(json_object_get(server, "expected_app_id")) && !new_app_id) {
            LOG_ERROR("Memory allocation failed for new_app_id in reload_config");
            free(new_secret);
            free(new_aud);
            json_decref(root);
            pthread_mutex_unlock(&config_mutex);
            return -1;
        }
        char *new_userdata = json_is_string(json_object_get(server, "userdata_file")) ? strdup(json_string_value(json_object_get(server, "userdata_file"))) : strdup(DEFAULT_USERDATA_FILE);
        if (!new_userdata) {
            LOG_ERROR("Memory allocation failed for new_userdata in reload_config");
            free(new_secret);
            free(new_aud);
            free(new_app_id);
            json_decref(root);
            pthread_mutex_unlock(&config_mutex);
            return -1;
        }
        char *new_pubkey = json_is_string(json_object_get(server, "pubkey_file")) ? strdup(json_string_value(json_object_get(server, "pubkey_file"))) : strdup(DEFAULT_PUBKEY_FILE);
        if (!new_pubkey) {
            LOG_ERROR("Memory allocation failed for new_pubkey in reload_config");
            free(new_secret);
            free(new_aud);
            free(new_app_id);
            free(new_userdata);
            json_decref(root);
            pthread_mutex_unlock(&config_mutex);
            return -1;
        }
        char *new_app_pubkey = json_is_string(json_object_get(server, "app_pubkey_file")) ? strdup(json_string_value(json_object_get(server, "app_pubkey_file"))) : strdup(DEFAULT_APP_PUBKEY_FILE);
        if (!new_app_pubkey) {
            LOG_ERROR("Memory allocation failed for new_app_pubkey in reload_config");
            free(new_secret);
            free(new_aud);
            free(new_app_id);
            free(new_userdata);
            free(new_pubkey);
            json_decref(root);
            pthread_mutex_unlock(&config_mutex);
            return -1;
        }
        int new_cleanup = json_integer_value(json_object_get(server, "cleanup_interval_seconds")) ?: DEFAULT_CLEANUP_INTERVAL_SECONDS;
        time_t new_jwks = json_integer_value(json_object_get(server, "jwks_refresh_interval")) ?: DEFAULT_JWKS_REFRESH_INTERVAL;
        int new_rl = json_integer_value(json_object_get(server, "max_requests_per_minute")) ?: DEFAULT_MAX_REQUESTS_PER_MINUTE;
        int new_drift = json_integer_value(json_object_get(server, "max_timestamp_drift")) ?: DEFAULT_MAX_TIMESTAMP_DRIFT;
        int new_nonce = json_integer_value(json_object_get(server, "max_nonce_entries")) ?: DEFAULT_MAX_NONCE_ENTRIES;
        int new_api_len = json_integer_value(json_object_get(server, "max_api_version_len")) ?: DEFAULT_MAX_API_VERSION_LEN;

        // Apply changes
        PORT = new_port;
        free(EXPECTED_APP_SECRET); EXPECTED_APP_SECRET = new_secret;
        free(EXPECTED_AUD); EXPECTED_AUD = new_aud;
        free(EXPECTED_APP_ID); EXPECTED_APP_ID = new_app_id;
        free(USERDATA_FILE); USERDATA_FILE = new_userdata;
        free(PUBKEY_FILE); PUBKEY_FILE = new_pubkey;
        free(APP_PUBKEY_FILE); APP_PUBKEY_FILE = new_app_pubkey;
        CLEANUP_INTERVAL_SECONDS = new_cleanup;
        JWKS_REFRESH_INTERVAL = new_jwks;
        MAX_REQUESTS_PER_MINUTE = new_rl;
        MAX_TIMESTAMP_DRIFT = new_drift;
        MAX_NONCE_ENTRIES = new_nonce;
        MAX_API_VERSION_LEN = new_api_len;

        printf("Reloaded server settings: port=%d, rate_limit=%d\n", PORT, MAX_REQUESTS_PER_MINUTE);
    }

    // Reload providers
    json_t *providers = json_object_get(root, "providers");
    if (providers && json_is_array(providers)) {
        // Clear old providers
        ProviderEntry *cur, *tmp;
        HASH_ITER(hh, provider_map, cur, tmp) {
            HASH_DEL(provider_map, cur);
            free_provider_entry(cur);
        }

        // Load new providers
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
                    LOG_ERROR("Memory allocation failed for new provider entry in reload_config");
                    continue;
                }
                entry->iss = normalize_iss(iss);
                if (!entry->iss) {
                    free(entry);
                    continue;
                }
                entry->jwks_url = strdup(jwks_url);
                if (!entry->jwks_url) {
                    LOG_ERROR("Memory allocation failed for jwks_url in reload_config");
                    free_provider_entry(entry);
                    continue;
                }
                entry->expected_aud = strdup(aud);
                if (!entry->expected_aud) {
                    LOG_ERROR("Memory allocation failed for expected_aud in reload_config");
                    free_provider_entry(entry);
                    continue;
                }
                entry->current_kid = NULL;
                entry->pubkey_pem = NULL;
                entry->last_refresh = 0;
                entry->ttl = JWKS_REFRESH_INTERVAL;
                if (pthread_mutex_init(&entry->lock, NULL) != 0) {
                    LOG_ERROR("pthread_mutex_init failed for new provider in reload_config");
                    free_provider_entry(entry);
                    continue;
                }
                HASH_ADD_STR(provider_map, iss, entry);
                printf("Reloaded provider: %s (%s)\n", name ? name : "unnamed", entry->iss);
                if (refresh_provider(entry) != 0) {
                    LOG_ERROR("Initial refresh failed for reloaded provider %s", entry->iss);
                }
            } else {
                LOG_ERROR("Invalid provider config for %s", name ? name : "unnamed");
            }
        }
    }

    json_decref(root);
    pthread_mutex_unlock(&config_mutex);
    printf("Config reload complete\n");
    return 0;
}

/* Config: Initialize providers from config.json */
/**
 * init_providers_from_config - Initialize provider map from config
 * @config: Parsed JSON config object
 *
 * Iterates providers array, creates ProviderEntry for each valid provider,
 * normalizes ISS, duplicates strings, initializes mutex, adds to hash map.
 */
void init_providers_from_config(json_t *config) {
    if (!config) {
        LOG_ERROR("NULL config in init_providers_from_config");
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
            entry->ttl = JWKS_REFRESH_INTERVAL;
            if (pthread_mutex_init(&entry->lock, NULL) != 0) {
                LOG_ERROR("pthread_mutex_init failed");
                free_provider_entry(entry);
                continue;
            }
            HASH_ADD_STR(provider_map, iss, entry);
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
    ProviderEntry *cur, *tmp;
    HASH_ITER(hh, provider_map, cur, tmp) {
        HASH_DEL(provider_map, cur);
        free_provider_entry(cur);
    }
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
    // first: static shared secret
    if (app_secret && EXPECTED_APP_SECRET && strcmp(app_secret, EXPECTED_APP_SECRET) == 0) {
        return 1;
    }

    // second: app JWT
    if (app_token) {
        jwt_t *jwt = NULL;
        if (jwt_decode(&jwt, app_token, (unsigned char *)app_pubkey, strlen(app_pubkey)) != 0) {
            LOG_ERROR("App JWT decode failed");
            return 0;
        }
        if (!jwt) {
            LOG_ERROR("jwt_decode returned NULL jwt");
            return 0;
        }
        const char *iss = jwt_get_grant(jwt, "iss");
        const char *aud = jwt_get_grant(jwt, "aud");
        const char *app_id = jwt_get_grant(jwt, "app_id");
        const char *exp_str = jwt_get_grant(jwt, "exp");
        if (!iss || strcmp(iss, "your-app") != 0) {
            LOG_ERROR("App JWT invalid issuer: %s", iss ? iss : "(null)");
            jwt_free(jwt);
            return 0;
        }
        if (!aud || !EXPECTED_AUD || strcmp(aud, EXPECTED_AUD) != 0) {
            LOG_ERROR("App JWT invalid audience: %s", aud ? aud : "(null)");
            jwt_free(jwt);
            return 0;
        }
        if (!app_id || !EXPECTED_APP_ID || strcmp(app_id, EXPECTED_APP_ID) != 0) {
            LOG_ERROR("App JWT invalid app_id: %s", app_id ? app_id : "(null)");
            jwt_free(jwt);
            return 0;
        }
        if (exp_str) {
            char *endptr;
            long exp = strtol(exp_str, &endptr, 10);
            if (*endptr != '\0' || exp < time(NULL)) {
                LOG_ERROR("App JWT expired");
                jwt_free(jwt);
                return 0;
            }
        }
        jwt_free(jwt);
        return 1;
    }
    return 0;
}

/* Trim leading/trailing whitespace in-place */
/**
 * trim_whitespace - Trim whitespace from string in-place
 * @str: String to trim (modified in-place)
 *
 * Removes leading/trailing whitespace. Handles empty strings.
 */
static void trim_whitespace(char *str) {
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
static int is_valid_version_format(const char *version) {
    if (!version || strlen(version) == 0 || strlen(version) > MAX_API_VERSION_LEN) {
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
 * @version: Version string
 *
 * Compares against supported_versions array.
 * Returns 1 if supported, 0 otherwise.
 */
static int is_supported_version(const char *version) {
    for (size_t i = 0; i < num_supported_versions; i++) {
        if (strcmp(version, supported_versions[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

/* Main robust version-checking function */
/**
 * parse_api_version - Parse and validate API version header
 * @input: Raw version string from header
 * @out_version: Buffer to store validated version
 * @out_size: Size of out_version buffer
 *
 * Trims, validates format, checks support, copies to output.
 * Returns 1 on success, 0 on failure (invalid or buffer too small).
 */
int parse_api_version(const char *input, char *out_version, size_t out_size) {
    if (!input || !out_version || out_size == 0) {
        LOG_ERROR("NULL input or out_version or zero out_size in parse_api_version");
        return 0;
    }

    char tmp[MAX_API_VERSION_LEN + 1];
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

    if (!is_supported_version(tmp)) {
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
 * @filename: Path to user data file
 * @name: User name
 * @email: User email
 *
 * Opens file with locking, writes User struct, closes safely.
 * Returns 1 on success, 0 on failure (logs errors).
 */
int save_user(const char *filename, const char *name, const char *email) {
    if (!filename || !name || !email) {
        LOG_ERROR("NULL filename, name, or email in save_user");
        return 0;
    }

    /* Open file safely using shim */
    int fd = open_user_file(filename);
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
    strncpy(u.name, name, MAX_NAME_LEN - 1);
    if (strlen(email) >= sizeof(u.email)) {
        LOG_ERROR("Email too long in save_user");
        unlock_file(fd);
        close(fd);
        return 0;
    }
    strncpy(u.email, email, MAX_EMAIL_LEN - 1);

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
 * @s: Name string
 *
 * Allows alnum, space, dash, underscore, dot. No injection chars.
 * OWASP Input Validation: Reject dangerous characters to prevent injection attacks.
 * Returns 1 if valid, 0 otherwise.
 */
static int is_valid_name(const char *s) {
    if (!s || strlen(s) == 0 || strlen(s) > MAX_NAME_LEN) return 0;
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
 * @s: Email string
 *
 * Uses POSIX regex for validation: ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$
 * OWASP Input Validation: Sanitize and validate email to prevent injection.
 * Returns 1 if valid, 0 otherwise.
 */
static int is_valid_email(const char *s) {
    if (!s || strlen(s) < 6 || strlen(s) > MAX_EMAIL_LEN) return 0;
    return regexec(&email_regex, s, 0, NULL, 0) == 0;
}

/* Connection context with buffers for accumulating POST data and total bytes, plus API version */
struct connection_info_struct {
    struct MHD_PostProcessor *postprocessor;
    char name[MAX_NAME_LEN + 1];
    size_t name_len;
    char email[MAX_EMAIL_LEN + 1];
    size_t email_len;
    size_t total_bytes; /* Track total POST data bytes */
    int authenticated;
    char client_ip[INET6_ADDRSTRLEN]; /* Support IPv6 */
    char api_version[MAX_API_VERSION_LEN + 1]; /* API version, e.g., "1.0", "1.1" */
};

/* Add security headers to every response */
/**
 * add_security_headers - Add security headers to MHD response
 * @response: MHD response object
 *
 * Adds headers for XSS, clickjacking, HSTS, CORS, cache control, referrer.
 * OWASP Security Headers: Enforce browser protections.
 */
static void add_security_headers(struct MHD_Response *response) {
    if (!response) {
        LOG_ERROR("NULL response in add_security_headers");
        return;
    }
    MHD_add_response_header(response, "X-Content-Type-Options", "nosniff");
    MHD_add_response_header(response, "X-Frame-Options", "DENY");
    MHD_add_response_header(response, "Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
    MHD_add_response_header(response, "Access-Control-Allow-Origin", "https://yourdomain.com");
    MHD_add_response_header(response, "Cache-Control", "no-store");
    MHD_add_response_header(response, "Referrer-Policy", "no-referrer");
    MHD_add_response_header(response, "Permissions-Policy", "geolocation=(), microphone=(), camera=()");
}

/* Send JSON response with status and headers */
/**
 * send_json_response - Send JSON response with security headers
 * @connection: MHD connection
 * @status_code: HTTP status code
 * @json_obj: JSON object to send
 *
 * Creates response from JSON, adds headers, queues response.
 * Returns MHD status (MHD_YES on success).
 */
static int send_json_response(struct MHD_Connection *connection, int status_code, json_t *json_obj) {
    if (!connection || !json_obj) {
        LOG_ERROR("NULL connection or json_obj in send_json_response");
        return MHD_NO;
    }
    char *json_str = json_dumps(json_obj, 0);
    if (!json_str) {
        LOG_ERROR("json_dumps failed in send_json_response");
        return MHD_NO;
    }
    struct MHD_Response *response = MHD_create_response_from_buffer(strlen(json_str), (void*) json_str, MHD_RESPMEM_MUST_FREE);
    if (!response) {
        LOG_ERROR("MHD_create_response_from_buffer failed");
        free(json_str);
        return MHD_NO;
    }
    MHD_add_response_header(response, "Content-Type", "application/json; charset=utf-8");
    add_security_headers(response);
    int ret = MHD_queue_response(connection, status_code, response);
    if (ret == MHD_NO) {
        LOG_ERROR("MHD_queue_response failed");
    }
    MHD_destroy_response(response);
    return ret;
}

/* POST data iterator - now accumulates data across chunks and enforces global MAX_BODY_SIZE */
/**
 * iterate_post - Process POST data chunks
 * @coninfo_cls: Connection info struct
 * @kind: MHD value kind
 * @key: Form field key
 * @filename: Upload filename (unused)
 * @content_type: Content type (unused)
 * @transfer_encoding: Encoding (unused)
 * @data: Data chunk
 * @off: Offset in field
 * @size: Size of chunk
 *
 * Accumulates data, enforces size limits, copies to buffers.
 * OWASP Input Validation: Enforce length limits to prevent buffer overflows.
 * Returns MHD_YES on success, MHD_NO on error.
 */
static int iterate_post(void *coninfo_cls, enum MHD_ValueKind kind, const char *key,
                        const char *filename, const char *content_type, const char *transfer_encoding,
                        const char *data, uint64_t off, size_t size) {
    if (!coninfo_cls || !key || !data) {
        LOG_ERROR("NULL coninfo_cls, key, or data in iterate_post");
        return MHD_NO;
    }
    struct connection_info_struct *con_info = (struct connection_info_struct *)coninfo_cls;

    /* Increment total bytes and reject if exceeded */
    if (size > SIZE_MAX - con_info->total_bytes) {
        LOG_ERROR("Size overflow in iterate_post");
        return MHD_NO;
    }
    con_info->total_bytes += size;
    if (con_info->total_bytes > MAX_BODY_SIZE) {
        return MHD_NO;  /* Abort request, triggers error response */
    }

    if (strcmp(key, "name") == 0 && off + size <= MAX_NAME_LEN) {
        if (off + size > MAX_NAME_LEN) {
            LOG_ERROR("Name field too long in iterate_post");
            return MHD_NO;
        }
        memcpy(con_info->name + off, data, size);
        con_info->name_len = off + size;
        con_info->name[con_info->name_len] = '\0'; /* Null-terminate */
    } else if (strcmp(key, "email") == 0 && off + size <= MAX_EMAIL_LEN) {
        if (off + size > MAX_EMAIL_LEN) {
            LOG_ERROR("Email field too long in iterate_post");
            return MHD_NO;
        }
        memcpy(con_info->email + off, data, size);
        con_info->email_len = off + size;
        con_info->email[con_info->email_len] = '\0'; /* Null-terminate */
    }
    return MHD_YES;
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
static int validate_nonce(const char *nonce) {
    if (!nonce || strlen(nonce) == 0 || strlen(nonce) >= 64) {
        LOG_ERROR("Invalid nonce length in validate_nonce");
        return 0; // Invalid nonce
    }

    if (pthread_mutex_lock(&nonce_table_lock) != 0) {
        LOG_ERROR("pthread_mutex_lock failed in validate_nonce");
        return 0;
    }

    /* Reject if table is full to prevent memory exhaustion */
    if (HASH_COUNT(nonce_table) >= MAX_NONCE_ENTRIES) {
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
 * Iterates table, frees entries older than MAX_TIMESTAMP_DRIFT.
 */
static void cleanup_nonce_table(void) {
    time_t now = time(NULL);
    unsigned removed = 0;
    if (pthread_mutex_lock(&nonce_table_lock) != 0) {
        LOG_ERROR("pthread_mutex_lock failed in cleanup_nonce_table");
        return;
    }
    NonceEntry *current, *tmp;
    HASH_ITER(hh, nonce_table, current, tmp) {
        if (now - current->timestamp > MAX_TIMESTAMP_DRIFT) {
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
 * @token: JWT token string
 *
 * Decodes header, finds provider, validates signature (refresh if needed),
 * checks claims. Returns 1 on success, 0 on failure.
 * OWASP JWT Best Practices: Validate signature, issuer, audience, expiration.
 */
int validate_jwt_user(const char *token) {
    if (!token) {
        LOG_ERROR("NULL token in validate_jwt_user");
        return 0;
    }
    jwt_t *jwt = NULL;
    int ok = 0;
    if (jwt_decode(&jwt, token, NULL, 0) != 0) {
        LOG_ERROR("JWT decode failed (header parse) for token");
        return 0;
    }
    if (!jwt) {
        LOG_ERROR("jwt_decode returned NULL jwt");
        return 0;
    }

    const char *kid = jwt_get_header(jwt, "kid");
    const char *iss = jwt_get_grant(jwt, "iss");
    const char *aud = jwt_get_grant(jwt, "aud");
    const char *exp_str = jwt_get_grant(jwt, "exp");
    const char *iat_str = jwt_get_grant(jwt, "iat");
    if (!iss || !aud || !exp_str || !iat_str) {
        LOG_ERROR("iss=%s kid=%s aud=%s verification=failed (missing claims)",
               iss ? iss : "(null)", kid ? kid : "(null)", aud ? aud : "(null)");
        jwt_free(jwt);
        return 0;
    }

    // Normalize iss for lookup
    char *normalized_iss = normalize_iss(iss);
    if (!normalized_iss) {
        jwt_free(jwt);
        return 0;
    }

    ProviderEntry *entry = NULL;
    HASH_FIND_STR(provider_map, normalized_iss, entry);
    free(normalized_iss);  // Free normalized iss after lookup
    if (!entry) {
        LOG_ERROR("iss=%s kid=%s aud=%s verification=failed (unknown issuer)",
               iss, kid ? kid : "(null)", aud);
        jwt_free(jwt);
        return 0;
    }

    // First attempt with cached key
    if (pthread_mutex_lock(&entry->lock) != 0) {
        LOG_ERROR("pthread_mutex_lock failed for provider lock");
        jwt_free(jwt);
        return 0;
    }
    const char *pubkey = entry->pubkey_pem;
    if (pthread_mutex_unlock(&entry->lock) != 0) {
        LOG_ERROR("pthread_mutex_unlock failed for provider lock");
        jwt_free(jwt);
        return 0;
    }

    if (jwt_decode(&jwt, token, (unsigned char *)pubkey, strlen(pubkey)) != 0) {
        // Retry once after refresh
        if (refresh_provider(entry) == 0) {
            if (pthread_mutex_lock(&entry->lock) != 0) {
                LOG_ERROR("pthread_mutex_lock failed after refresh");
                jwt_free(jwt);
                return 0;
            }
            pubkey = entry->pubkey_pem;
            if (pthread_mutex_unlock(&entry->lock) != 0) {
                LOG_ERROR("pthread_mutex_unlock failed after refresh");
                jwt_free(jwt);
                return 0;
            }
            if (jwt_decode(&jwt, token, (unsigned char *)pubkey, strlen(pubkey)) == 0) {
                ok = 1;
            } else {
                LOG_ERROR("JWT decode failed after refresh");
            }
        } else {
            LOG_ERROR("Refresh provider failed");
        }
    } else {
        ok = 1;
    }

    if (ok) {
        // Check aud
        if (strcmp(aud, entry->expected_aud) != 0) {
            LOG_ERROR("iss=%s kid=%s aud=%s verification=failed (aud mismatch)", iss, kid ? kid : "(null)", aud);
            ok = 0;
        }

        // Check expiration
        {
            char *endptr;
            long exp = strtol(exp_str, &endptr, 10);
            if (*endptr != '\0' || exp < time(NULL)) {
                LOG_ERROR("iss=%s kid=%s aud=%s verification=failed (expired)", iss, kid ? kid : "(null)", aud);
                ok = 0;
            }
        }

        // Check issued-at and replay protection
        {
            char *endptr;
            long iat = strtol(iat_str, &endptr, 10);
            if (*endptr != '\0' || iat < time(NULL) - MAX_TIMESTAMP_DRIFT || iat > time(NULL) + MAX_TIMESTAMP_DRIFT) {
                LOG_ERROR("iss=%s kid=%s aud=%s verification=failed (iat out of range)", iss, kid ? kid : "(null)", aud);
                ok = 0;
            }
        }
    }

    printf("[JWT] iss=%s kid=%s aud=%s verification=%s\n", iss, kid ? kid : "(null)", aud, ok ? "success" : "failed");
    jwt_free(jwt);
    return ok;
}

/* Check OAuth Bearer token - supports user JWT or app auth */
/**
 * check_oauth_bearer - Validate Bearer token from Authorization header
 * @connection: MHD connection
 *
 * Extracts Bearer token, validates user JWT or app auth.
 * Returns 1 on success, 0 on failure.
 */
static int check_oauth_bearer(struct MHD_Connection *connection) {
    if (!connection) {
        LOG_ERROR("NULL connection in check_oauth_bearer");
        return 0;
    }
    const char *auth_header = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Authorization");
    const char *app_secret = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "X-App-Secret");
    const char *app_token = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "X-App-Token");

    // Try user JWT first
    if (auth_header && strncmp(auth_header, "Bearer ", 7) == 0) {
        const char *token = auth_header + 7;
        if (validate_jwt_user(token)) {
            /* Check nonce for replay protection */
            const char *nonce = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "X-Nonce");
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
static void cleanup_expired_entries(void) {
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
        sleep(CLEANUP_INTERVAL_SECONDS);

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
static int check_rate_limit(const char *client_ip) {
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

    if (entry->request_count >= MAX_REQUESTS_PER_MINUTE) {
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
 * answer_to_connection - MHD request handler
 * @cls: Unused
 * @connection: MHD connection
 * @url: Request URL
 * @method: HTTP method
 * @version: HTTP version
 * @upload_data: Upload data
 * @upload_data_size: Size of upload data
 * @con_cls: Connection context
 *
 * Handles rate limit, auth, POST processing, validation, response.
 * Returns MHD_YES/MHD_NO.
 */
static int answer_to_connection(void *cls, struct MHD_Connection *connection, const char *url,
                                const char *method, const char *version, const char *upload_data,
                                size_t *upload_data_size, void **con_cls) {
    if (!connection || !url || !method) {
        LOG_ERROR("NULL connection, url, or method in answer_to_connection");
        return MHD_NO;
    }
    if (*con_cls == NULL) {
        struct connection_info_struct *con_info = calloc(1, sizeof(struct connection_info_struct));
        if (!con_info) {
            LOG_ERROR("Memory allocation failed for connection_info_struct");
            return MHD_NO;
        }
        const union MHD_ConnectionInfo *ci = MHD_get_connection_info(connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS);
        if (ci && ci->client_addr) {
            const struct sockaddr *sa = ci->client_addr;
            if (sa->sa_family == AF_INET) {
                const struct sockaddr_in *sa_in = (const struct sockaddr_in *)sa;
                if (inet_ntop(AF_INET, &(sa_in->sin_addr), con_info->client_ip, INET_ADDRSTRLEN) == NULL) {
                    perror("[ERROR] inet_ntop for IPv4");
                    con_info->client_ip[0] = '\0';
                }
            } else if (sa->sa_family == AF_INET6) {
                const struct sockaddr_in6 *sa_in6 = (const struct sockaddr_in6 *)sa;
                if (inet_ntop(AF_INET6, &(sa_in6->sin6_addr), con_info->client_ip, INET6_ADDRSTRLEN) == NULL) {
                    perror("[ERROR] inet_ntop for IPv6");
                    con_info->client_ip[0] = '\0';
                }
            } else {
                con_info->client_ip[0] = '\0';
            }
        } else {
            con_info->client_ip[0] = '\0';
        }

        /* Parse API version with robust validation */
        char api_version[MAX_API_VERSION_LEN + 1];
        const char *ver_header = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "X-API-Version");
        if (!ver_header) ver_header = "1.0"; // default

        if (!parse_api_version(ver_header, api_version, sizeof(api_version))) {
            json_t *error_json = json_pack("{s:s}", "error", "Unsupported or invalid API version");
            if (!error_json) {
                LOG_ERROR("json_pack failed for API version error");
                free(con_info);
                return MHD_NO;
            }
            int ret = send_json_response(connection, MHD_HTTP_BAD_REQUEST, error_json);
            json_decref(error_json);
            free(con_info);
            return ret;
        }

        if (strlen(api_version) >= sizeof(con_info->api_version)) {
            LOG_ERROR("API version too long for buffer");
            free(con_info);
            return MHD_NO;
        }
        strncpy(con_info->api_version, api_version, sizeof(con_info->api_version) - 1);
        con_info->api_version[sizeof(con_info->api_version) - 1] = '\0';

        /* Check Content-Length for POST requests to prevent payload too large and overflow */
        if (strcmp(method, "POST") == 0) {
            const char *content_length_str = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Content-Length");
            if (content_length_str) {
                long long content_length = atoll(content_length_str);
                if (content_length < 0 || content_length > MAX_BODY_SIZE) {
                    json_t *error_json = json_pack("{s:s}", "error", "Payload too large");
                    if (!error_json) {
                        LOG_ERROR("json_pack failed for payload error");
                        free(con_info);
                        return MHD_NO;
                    }
                    int ret = send_json_response(connection, MHD_HTTP_PAYLOAD_TOO_LARGE, error_json);
                    json_decref(error_json);
                    free(con_info);
                    return ret;
                }
            }
            con_info->postprocessor = MHD_create_post_processor(connection, MAX_BODY_SIZE, &iterate_post, con_info);
            if (!con_info->postprocessor) {
                LOG_ERROR("MHD_create_post_processor failed");
                free(con_info);
                return MHD_NO;
            }
        }
        *con_cls = con_info;
        return MHD_YES;
    }

    struct connection_info_struct *con_info = *con_cls;

    if (!check_rate_limit(con_info->client_ip)) {
        json_t *error_json = json_pack("{s:s}", "error", "Rate limit exceeded. Please try again later.");
        if (!error_json) {
            LOG_ERROR("json_pack failed for rate limit error");
            return MHD_NO;
        }
        int ret = send_json_response(connection, MHD_HTTP_TOO_MANY_REQUESTS, error_json);
        json_decref(error_json);
        return ret;
    }

    if (strcmp(method, "POST") == 0 && strcmp(url, "/hello") == 0) {
        if (!check_oauth_bearer(connection)) {
            json_t *error_json = json_pack("{s:s}", "error", "Unauthorized. Valid JWT Bearer token required.");
            if (!error_json) {
                LOG_ERROR("json_pack failed for auth error");
                return MHD_NO;
            }
            int ret = send_json_response(connection, MHD_HTTP_UNAUTHORIZED, error_json);
            json_decref(error_json);
            return ret;
        }
        if (*upload_data_size != 0) {
            int post_ret = MHD_post_process(con_info->postprocessor, upload_data, *upload_data_size);
            if (post_ret == MHD_NO) {
                // Post processing failed, likely due to size exceeded in iterator
                json_t *error_json = json_pack("{s:s}", "error", "Payload too large");
                if (!error_json) {
                    LOG_ERROR("json_pack failed for post process error");
                    return MHD_NO;
                }
                int ret = send_json_response(connection, MHD_HTTP_PAYLOAD_TOO_LARGE, error_json);
                json_decref(error_json);
                return ret;
            }
            *upload_data_size = 0;
            return MHD_YES;
        }
        if (con_info->name_len == 0 || con_info->email_len == 0) {
            json_t *error_json = json_pack("{s:s}", "error", "Missing required fields: name and email");
            if (!error_json) {
                LOG_ERROR("json_pack failed for missing fields error");
                return MHD_NO;
            }
            int ret = send_json_response(connection, MHD_HTTP_BAD_REQUEST, error_json);
            json_decref(error_json);
            return ret;
        }
        if (!is_valid_name(con_info->name) || !is_valid_email(con_info->email)) {
            json_t *error_json = json_pack("{s:s}", "error", "Invalid name or email format");
            if (!error_json) {
                LOG_ERROR("json_pack failed for validation error");
                return MHD_NO;
            }
            int ret = send_json_response(connection, MHD_HTTP_BAD_REQUEST, error_json);
            json_decref(error_json);
            return ret;
        }
        if (!save_user(USERDATA_FILE, con_info->name, con_info->email)) {
            json_t *error_json = json_pack("{s:s}", "error", "Failed to save user data");
            if (!error_json) {
                LOG_ERROR("json_pack failed for save error");
                return MHD_NO;
            }
            int ret = send_json_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, error_json);
            json_decref(error_json);
            return ret;
        }
        time_t now = time(NULL);
        printf("[%ld] Request from %s: name=%s, email=%s\n", now, con_info->client_ip, con_info->name, con_info->email);
        char greeting[256];
        /* Branch logic based on API version */
        if (strcmp(con_info->api_version, "1.0") == 0) {
            // existing behavior
            if (snprintf(greeting, sizeof(greeting), "Hello, %s <%s>", con_info->name, con_info->email) < 0) {
                LOG_ERROR("snprintf failed for greeting");
                return MHD_NO;
            }
        } else if (strcmp(con_info->api_version, "1.1") == 0) {
            // future behavior, e.g., include timestamp
            time_t now = time(NULL);
            if (snprintf(greeting, sizeof(greeting), "Hello, %s <%s> at %ld", con_info->name, con_info->email, now) < 0) {
                LOG_ERROR("snprintf failed for greeting 1.1");
                return MHD_NO;
            }
        } else {
            // unknown version: reject
            json_t *error_json = json_pack("{s:s}", "error", "Unsupported API version");
            if (!error_json) {
                LOG_ERROR("json_pack failed for unsupported version error");
                return MHD_NO;
            }
            int ret = send_json_response(connection, MHD_HTTP_BAD_REQUEST, error_json);
            json_decref(error_json);
            return ret;
        }
        json_t *json_resp = json_pack("{s:s, s:s}", "greeting", greeting, "version", con_info->api_version);
        if (!json_resp) {
            LOG_ERROR("json_pack failed for response");
            return MHD_NO;
        }
        int ret = send_json_response(connection, MHD_HTTP_OK, json_resp);
        json_decref(json_resp);

        /* Zero sensitive buffers after processing */
        explicit_bzero(con_info->name, sizeof(con_info->name));
        explicit_bzero(con_info->email, sizeof(con_info->email));
        con_info->name_len = con_info->email_len = 0;

        return ret;
    }

    if (strcmp(method, "OPTIONS") == 0) {
        struct MHD_Response *response = MHD_create_response_from_buffer(0, "", MHD_RESPMEM_PERSISTENT);
        if (!response) {
            LOG_ERROR("MHD_create_response_from_buffer failed for OPTIONS");
            return MHD_NO;
        }
        MHD_add_response_header(response, "Access-Control-Allow-Methods", "POST, OPTIONS");
        MHD_add_response_header(response, "Access-Control-Allow-Headers", "Content-Type, Authorization, X-Nonce, X-API-Version, X-App-Secret, X-App-Token");
        MHD_add_response_header(response, "Access-Control-Allow-Origin", "https://yourdomain.com");
        add_security_headers(response);
        int ret = MHD_queue_response(connection, MHD_HTTP_NO_CONTENT, response);
        if (ret == MHD_NO) {
            LOG_ERROR("MHD_queue_response failed for OPTIONS");
        }
        MHD_destroy_response(response);
        return ret;
    }

    json_t *error_json = json_pack("{s:s}", "error", "Invalid endpoint or method");
    if (!error_json) {
        LOG_ERROR("json_pack failed for invalid endpoint error");
        return MHD_NO;
    }
    int ret = send_json_response(connection, MHD_HTTP_NOT_FOUND, error_json);
    json_decref(error_json);
    return ret;
}

/* Proper connection cleanup */
/**
 * request_completed - MHD connection cleanup callback
 * @cls: Unused
 * @connection: MHD connection
 * @con_cls: Connection context to free
 * @toe: Termination reason
 *
 * Frees postprocessor and connection_info_struct.
 */
static void request_completed(void *cls, struct MHD_Connection *connection, void **con_cls, enum MHD_RequestTerminationCode toe) {
    struct connection_info_struct *con_info = *con_cls;
    if (con_info) {
        if (con_info->postprocessor) {
            MHD_destroy_post_processor(con_info->postprocessor);
        }
        free(con_info);
        *con_cls = NULL;
    }
}

int main() {
    const char *key_path = "/etc/ssl/private/key.pem";
    const char *cert_path = "/etc/ssl/certs/cert.pem";

    // Load config and set globals
    json_t *config = load_config(CONFIG_FILE);
    if (!config) {
        return 1;
    }

    // Compile email regex
    if (regcomp(&email_regex, "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", REG_EXTENDED | REG_NOSUB) != 0) {
        LOG_ERROR("Failed to compile email regex");
        json_decref(config);
        return 1;
    }
    email_regex_compiled = 1;

    char *tls_key_pem = read_file(key_path);
    char *tls_cert_pem = read_file(cert_path);

    if (pthread_mutex_lock(&jwt_pubkey_lock) != 0) {
        LOG_ERROR("pthread_mutex_lock failed for jwt_pubkey_lock in main");
        json_decref(config);
        free(tls_key_pem);
        free(tls_cert_pem);
        return 1;
    }
    jwt_pubkey = read_file(PUBKEY_FILE);
    app_pubkey = read_file(APP_PUBKEY_FILE);
    if (pthread_mutex_unlock(&jwt_pubkey_lock) != 0) {
        LOG_ERROR("pthread_mutex_unlock failed for jwt_pubkey_lock in main");
    }

    if (!jwt_pubkey || !app_pubkey) {
        LOG_ERROR("Failed to read or validate JWT public keys");
        free(tls_key_pem);
        free(tls_cert_pem);
        if (jwt_pubkey) free(jwt_pubkey);
        if (app_pubkey) free(app_pubkey);
        json_decref(config);
        return 1;
    }
    if (!tls_key_pem || !tls_cert_pem) {
        LOG_ERROR("Failed to read TLS key or certificate");
        free(tls_key_pem);
        free(tls_cert_pem);
        if (pthread_mutex_lock(&jwt_pubkey_lock) != 0) {
            LOG_ERROR("pthread_mutex_lock failed");
        }
        free(jwt_pubkey);
        free(app_pubkey);
        jwt_pubkey = NULL;
        app_pubkey = NULL;
        if (pthread_mutex_unlock(&jwt_pubkey_lock) != 0) {
            LOG_ERROR("pthread_mutex_unlock failed");
        }
        json_decref(config);
        return 1;
    }

    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        LOG_ERROR("curl_global_init failed");
        free(tls_key_pem);
        free(tls_cert_pem);
        if (pthread_mutex_lock(&jwt_pubkey_lock) != 0) {
            LOG_ERROR("pthread_mutex_lock failed");
        }
        free(jwt_pubkey);
        free(app_pubkey);
        jwt_pubkey = NULL;
        app_pubkey = NULL;
        if (pthread_mutex_unlock(&jwt_pubkey_lock) != 0) {
            LOG_ERROR("pthread_mutex_unlock failed");
        }
        json_decref(config);
        return 1;
    }
    init_providers_from_config(config);
    json_decref(config); // Done with config

    /* Start cleanup thread */
    if (pthread_create(&cleanup_thread, NULL, cleanup_thread_func, NULL) != 0) {
        LOG_ERROR("Failed to create cleanup thread");
        free(tls_key_pem);
        free(tls_cert_pem);
        if (pthread_mutex_lock(&jwt_pubkey_lock) != 0) {
            LOG_ERROR("pthread_mutex_lock failed");
        }
        free(jwt_pubkey);
        free(app_pubkey);
        jwt_pubkey = NULL;
        app_pubkey = NULL;
        if (pthread_mutex_unlock(&jwt_pubkey_lock) != 0) {
            LOG_ERROR("pthread_mutex_unlock failed");
        }
        destroy_jwks_providers();
        curl_global_cleanup();
        return 1;
    }

    // Register signal/console handlers using shims
#ifdef _WIN32
    if (!SetConsoleCtrlHandler(console_handler, TRUE)) {
        LOG_ERROR("SetConsoleCtrlHandler failed");
        free(tls_key_pem);
        free(tls_cert_pem);
        if (pthread_mutex_lock(&jwt_pubkey_lock) != 0) {
            LOG_ERROR("pthread_mutex_lock failed");
        }
        free(jwt_pubkey);
        free(app_pubkey);
        jwt_pubkey = NULL;
        app_pubkey = NULL;
        if (pthread_mutex_unlock(&jwt_pubkey_lock) != 0) {
            LOG_ERROR("pthread_mutex_unlock failed");
        }
        pthread_cancel(cleanup_thread);
        pthread_join(cleanup_thread, NULL);
        destroy_jwks_providers();
        curl_global_cleanup();
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
        if (pthread_mutex_lock(&jwt_pubkey_lock) != 0) {
            LOG_ERROR("pthread_mutex_lock failed");
        }
        free(jwt_pubkey);
        free(app_pubkey);
        jwt_pubkey = NULL;
        app_pubkey = NULL;
        if (pthread_mutex_unlock(&jwt_pubkey_lock) != 0) {
            LOG_ERROR("pthread_mutex_unlock failed");
        }
        pthread_cancel(cleanup_thread);
        pthread_join(cleanup_thread, NULL);
        destroy_jwks_providers();
        curl_global_cleanup();
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
        if (pthread_mutex_lock(&jwt_pubkey_lock) != 0) {
            LOG_ERROR("pthread_mutex_lock failed");
        }
        free(jwt_pubkey);
        free(app_pubkey);
        jwt_pubkey = NULL;
        app_pubkey = NULL;
        if (pthread_mutex_unlock(&jwt_pubkey_lock) != 0) {
            LOG_ERROR("pthread_mutex_unlock failed");
        }
        pthread_cancel(cleanup_thread);
        pthread_join(cleanup_thread, NULL);
        destroy_jwks_providers();
        curl_global_cleanup();
        return 1;
    }
#endif

    struct MHD_Daemon *daemon;
    daemon = MHD_start_daemon(
        MHD_USE_THREAD_PER_CONNECTION | MHD_USE_SSL,
        PORT,
        NULL, NULL,
        &answer_to_connection, NULL,
        MHD_OPTION_NOTIFY_COMPLETED, request_completed, NULL,
        MHD_OPTION_HTTPS_MEM_KEY, tls_key_pem,
        MHD_OPTION_HTTPS_MEM_CERT, tls_cert_pem,
        MHD_OPTION_END);

    free(tls_key_pem);
    free(tls_cert_pem);

    if (NULL == daemon) {
        LOG_ERROR("Failed to start HTTPS server");
        if (pthread_cancel(cleanup_thread) != 0) {
            LOG_ERROR("pthread_cancel failed");
        }
        if (pthread_join(cleanup_thread, NULL) != 0) {
            LOG_ERROR("pthread_join failed");
        }
        if (pthread_mutex_lock(&jwt_pubkey_lock) != 0) {
            LOG_ERROR("pthread_mutex_lock failed");
        }
        free(jwt_pubkey);
        free(app_pubkey);
        jwt_pubkey = NULL;
        app_pubkey = NULL;
        if (pthread_mutex_unlock(&jwt_pubkey_lock) != 0) {
            LOG_ERROR("pthread_mutex_unlock failed");
        }
        destroy_jwks_providers();
        curl_global_cleanup();
        return 1;
    }

    printf("Secure REST server running with HTTPS on port %d\n", PORT);
    printf("JWT validation enabled. Public key loaded from: %s\n", PUBKEY_FILE);
    printf("App pubkey loaded from: %s\n", APP_PUBKEY_FILE);
    printf("Config loaded from: %s\n", CONFIG_FILE);
    printf("Rate limiting: %d requests per minute per IP\n", MAX_REQUESTS_PER_MINUTE);
    printf("Replay protection: JWT iat check (±%d seconds) and X-Nonce validation (max %d entries)\n", MAX_TIMESTAMP_DRIFT, MAX_NONCE_ENTRIES);
    printf("Cleanup thread running every %d seconds\n", CLEANUP_INTERVAL_SECONDS);
    printf("Press Ctrl+C to shutdown gracefully.\n");
    printf("Send SIGHUP (kill -HUP <pid>) to reload config at runtime.\n");
    printf("Try: curl -k -X POST -H \"Authorization: Bearer <JWT>\" -H \"X-Nonce: <unique-nonce>\" -H \"X-API-Version: 1.1\" -d \"name=Terry&email=terry@example.com\" https://127.0.0.1:8443/hello\n");
    printf("Or for app auth: curl -k -X POST -H \"X-App-Secret: replace_with_secure_random_value\" -H \"X-API-Version: 1.1\" -d \"name=Terry&email=terry@example.com\" https://127.0.0.1:8443/hello\n");
    printf("User data saved in: %s\n", USERDATA_FILE);

    /* Wait for shutdown signal */
    while (!shutdown_flag) {
        if (config_reload_requested) {
            fprintf(stderr, "Reloading config...\n");
            if (reload_config(CONFIG_FILE) != 0) {
                LOG_ERROR("Config reload failed");
            }
            config_reload_requested = 0;
        }
        if (pause() != 0 && errno != EINTR) {
            perror("[ERROR] pause");
        }
    }

    if (MHD_stop_daemon(daemon) != MHD_YES) {
        LOG_ERROR("MHD_stop_daemon failed");
    }

    /* Cleanup */
    free_rate_limit_table();
    free_nonce_table();

    if (pthread_mutex_lock(&jwt_pubkey_lock) != 0) {
        LOG_ERROR("pthread_mutex_lock failed in cleanup");
    }
    free(jwt_pubkey);
    free(app_pubkey);
    jwt_pubkey = NULL;
    app_pubkey = NULL;
    if (pthread_mutex_unlock(&jwt_pubkey_lock) != 0) {
        LOG_ERROR("pthread_mutex_unlock failed in cleanup");
    }

    destroy_jwks_providers();
    curl_global_cleanup();

    // Free config globals
    free(EXPECTED_APP_SECRET);
    free(EXPECTED_AUD);
    free(EXPECTED_APP_ID);
    free(USERDATA_FILE);
    free(PUBKEY_FILE);
    free(APP_PUBKEY_FILE);

    // Free email regex
    if (email_regex_compiled) {
        regfree(&email_regex);
    }

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
      "name": "google",
      "iss": "accounts.google.com",
      "jwks_url": "https://www.googleapis.com/oauth2/v3/certs",
      "expected_aud": "YOUR_GOOGLE_CLIENT_ID"
    },
    {
      "name": "microsoft",
      "iss": "login.microsoftonline.com",
      "jwks_url": "https://login.microsoftonline.com/common/discovery/v2.0/keys",
      "expected_aud": "YOUR_MICROSOFT_APP_ID"
    },
    {
      "name": "auth0",
      "iss": "https://YOUR_DOMAIN.auth0.com/",
      "jwks_url": "https://YOUR_DOMAIN.auth0.com/.well-known/jwks.json",
      "expected_aud": "YOUR_AUTH0_CLIENT_ID"
    },
    {
      "name": "okta",
      "iss": "https://YOUR_OKTA_DOMAIN/oauth2/default",
      "jwks_url": "https://YOUR_OKTA_DOMAIN/oauth2/default/v1/keys",
      "expected_aud": "YOUR_OKTA_CLIENT_ID"
    },
    {
      "name": "apple",
      "iss": "https://appleid.apple.com",
      "jwks_url": "https://appleid.apple.com/auth/keys",
      "expected_aud": "YOUR_APP_APP_ID"
    }
  ]
}
================================================================================
*/

}
