# Migration from libmicrohttpd to CivetWeb

## Overview
This document describes the migration from libmicrohttpd to CivetWeb in the hello world REST API server.

## Why CivetWeb?
- **Active Development**: CivetWeb is actively maintained with regular updates
- **OpenSSL Support**: Native support for OpenSSL 3.0 with SSL/TLS
- **Cross-Platform**: Works on Linux, macOS, and Windows
- **Embedded-Friendly**: Designed to be embedded in applications
- **Thread-Safe**: Built-in thread-safe request handling

## Key Changes

### 1. HTTP Server Initialization
**Before (libmicrohttpd):**
```c
struct MHD_Daemon *daemon;
daemon = MHD_start_daemon(
    MHD_USE_THREAD_PER_CONNECTION | MHD_USE_SSL,
    port, NULL, NULL,
    &answer_to_connection, &ctx,
    MHD_OPTION_HTTPS_MEM_KEY, tls_key_pem,
    MHD_OPTION_HTTPS_MEM_CERT, tls_cert_pem,
    MHD_OPTION_END);
```

**After (CivetWeb):**
```c
const char *options[] = {
    "listening_ports", "8443s",  // 's' suffix enables SSL
    "ssl_certificate", "/tmp/server_cert.pem",
    "ssl_private_key", "/tmp/server_key.pem",
    "num_threads", "50",
    NULL
};

struct mg_callbacks callbacks;
memset(&callbacks, 0, sizeof(callbacks));
callbacks.begin_request = answer_to_connection;

struct mg_context *mg_ctx = mg_start(&callbacks, &ctx, options);
```

### 2. Request Handler Signature
**Before (libmicrohttpd):**
```c
static int answer_to_connection(void *cls, struct MHD_Connection *connection,
                               const char *url, const char *method,
                               const char *version, const char *upload_data,
                               size_t *upload_data_size, void **con_cls)
```

**After (CivetWeb):**
```c
static int answer_to_connection(struct mg_connection *conn, void *cbdata)
```

### 3. Getting Request Information
**Before (libmicrohttpd):**
```c
const char *header = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Authorization");
```

**After (CivetWeb):**
```c
const struct mg_request_info *req_info = mg_get_request_info(conn);
const char *header = mg_get_header(conn, "Authorization");
const char *method = req_info->request_method;
const char *uri = req_info->request_uri;
```

### 4. Reading POST Data
**Before (libmicrohttpd):**
```c
struct MHD_PostProcessor *postprocessor = MHD_create_post_processor(...);
MHD_post_process(postprocessor, upload_data, *upload_data_size);
```

**After (CivetWeb):**
```c
char post_buffer[4096];
int data_len = mg_read(conn, post_buffer, sizeof(post_buffer) - 1);
post_buffer[data_len] = '\0';
// Parse the data manually
```

### 5. Sending Responses
**Before (libmicrohttpd):**
```c
struct MHD_Response *response = MHD_create_response_from_buffer(len, data, mode);
MHD_add_response_header(response, "Content-Type", "application/json");
MHD_queue_response(connection, status_code, response);
MHD_destroy_response(response);
```

**After (CivetWeb):**
```c
mg_printf(conn, "HTTP/1.1 %d %s\r\n", status_code, status_text);
mg_printf(conn, "Content-Type: application/json\r\n");
mg_printf(conn, "Content-Length: %zu\r\n\r\n", strlen(json_str));
mg_write(conn, json_str, strlen(json_str));
```

### 6. Server Shutdown
**Before (libmicrohttpd):**
```c
MHD_stop_daemon(daemon);
```

**After (CivetWeb):**
```c
mg_stop(mg_ctx);
```

## Build Instructions

### Compile CivetWeb (once)
```bash
gcc -c civetweb.c -o civetweb.o -DUSE_SSL -DNO_SSL_DL -DOPENSSL_API_3_0 -I. -fPIC
```

### Compile Application
```bash
gcc -c hello.c -o hello.o -I. -Wno-format-truncation -Wno-deprecated-declarations
gcc hello.o civetweb.o -o server -lcurl -lssl -lcrypto -ljansson -ljwt -lpthread -ldl
```

## Functionality Preserved
All original functionality has been preserved:
- ✅ HTTPS with OpenSSL
- ✅ JWT validation with JWKS
- ✅ Rate limiting per IP
- ✅ Nonce replay protection
- ✅ POST data processing
- ✅ Security headers (HSTS, CSP, etc.)
- ✅ API versioning
- ✅ Dynamic config reload
- ✅ Thread-safe operations
- ✅ Graceful shutdown

## Dependencies
- **Removed**: libmicrohttpd
- **Added**: CivetWeb (included in repository)
- **Required**: OpenSSL 3.0+, libcurl, jansson, libjwt, pthread

## Notes
- CivetWeb requires TLS certificates as files, not in-memory strings
- Temporary certificate files are created in `/tmp/` at startup
- The server now uses CivetWeb's event-driven architecture
- Connection-specific data is handled differently (no per-connection state)
- POST data is read in a single `mg_read()` call instead of streaming chunks
