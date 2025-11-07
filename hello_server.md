# Secure REST Server (hello.c) – Technical Documentation

## 1. Overview
`hello.c` implements a production-oriented, single-binary HTTPS REST microservice written in C. It provides:
- JWT-based user authentication with multi-issuer JWKS auto-refresh
- Optional application authentication (shared secret or JWT)
- Rate limiting and replay (nonce) protection
- API versioning via `X-API-Version` header
- Hardened input validation and structured JSON responses
- Dynamic configuration reload (SIGHUP on POSIX / simulated via Ctrl+Break on Windows)
- Graceful shutdown & background maintenance thread
- Cross-platform abstractions (Linux, macOS, Windows shims)
- Secure file persistence with locking and anti-symlink (`O_NOFOLLOW`) protections

Primary exposed endpoint: `POST /hello` – registers a user (name + email) and returns a greeting.

---

## 2. High-Level Data Flow
```
Client -> TLS Listener (MHD) -> Connection Init -> Rate Limit Check
      -> API Version Parse -> Auth (User JWT or App) -> Nonce Replay Check
      -> POST Body Streaming + Validation -> Persist User -> JSON Response
                              \
                               -> Error Path -> JSON Error Object
```

Maintenance path:
```
Background Cleanup Thread:
  - Expired rate limit windows
  - Expired nonces (replay table)
  - Observability (counts)
```

Config reload path:
```
SIGHUP / Ctrl+Break -> reload_config() -> Re-parse config -> Rebuild provider map ->
JWKS refresh (lazy / on-demand)
```

---

## 3. Build Instructions
(Exact flags depend on your platform & installed libraries)

Linux (recommended 64-bit):
```bash
gcc -o server hello.c -lmicrohttpd -lcurl -lssl -lcrypto -ljansson -ljwt -pthread
```

macOS:
```bash
clang -o server hello.c -lmicrohttpd -lcurl -lssl -lcrypto -ljansson -ljwt
```

Windows (MSVC):
```
cl hello.c /I"path\to\deps\include" /link ws2_32.lib User32.lib Advapi32.lib Crypt32.lib
```
MinGW-w64:
```bash
x86_64-w64-mingw32-gcc hello.c -o server.exe -lcurl -lssl -lcrypto -ljansson -ljwt -pthread -lmicrohttpd
```

---

## 4. Runtime Execution
```
./server
```
Requirements (defaults if not overridden):
- `config.json` in working directory
- TLS key: `/etc/ssl/private/key.pem`
- TLS cert: `/etc/ssl/certs/cert.pem`
- JWT public key files: `public.pem`, `app_pub.pem` (paths configurable)

Reload configuration (POSIX):
```
kill -HUP <pid>
```
Graceful shutdown:
- POSIX: `Ctrl+C` (SIGINT)
- Windows: `Ctrl+C`

---

## 5. Configuration (config.json)
Example (embedded at EOF of source):
```json
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
    }
  ]
}
```

Key fields:
- Port & file paths
- `expected_app_secret`: shared secret (fallback auth path)
- `expected_aud`, `expected_app_id`: claim validation targets
- JWKS refresh interval (default TTL override; actual TTL may be taken from `Cache-Control: max-age=...`)
- Rate limiting & replay protection sizing knobs
- Provider list: each includes `iss`, `jwks_url`, per-issuer audience

---

## 6. Security Features
| Feature | Mechanism | Notes |
|---------|-----------|-------|
| TLS | libmicrohttpd HTTPS mode | In-memory cert/key via `MHD_OPTION_HTTPS_MEM_*` |
| JWT Validation | libjwt + dynamic JWKS fetch | Multi-issuer support; KID-based refresh |
| JWKS Caching | ProviderEntry TTL & periodic selective refresh | Respects `Cache-Control: max-age=` |
| Audience / Issuer Checks | Strict string match + normalization | Trailing slash + whitespace trimmed |
| Exp / IAT Bounds | Numeric conversion with drift window | ± `MAX_TIMESTAMP_DRIFT` seconds |
| Replay Protection | `X-Nonce` stored in uthash | Table size capped at `MAX_NONCE_ENTRIES` |
| Rate Limiting | Per-IP window (60s) | Hard cap: `MAX_REQUESTS_PER_MINUTE` |
| Input Validation | Length + character whitelists | Prevents injection primitives |
| File Safety | `O_NOFOLLOW`, locking, fixed-size struct writes | Avoids symlink race / corruption |
| Memory Hygiene | Zeroing sensitive buffers (`explicit_bzero`) | Post-response sanitation |
| Security Headers | HSTS, X-Frame-Options, etc. | Added per response |
| Graceful Shutdown | Signal handlers | Ensures cleanup of dynamic tables |
| Config Reload | Atomic rebuild under mutex | Providers map reinitialized |

---

## 7. API Surface

### 7.1 Endpoints
1. `POST /hello`
   - Form-encoded body: `name=...&email=...`
   - Headers (required):
     - Authentication:
       - Option A (User JWT): `Authorization: Bearer <token>`, plus `X-Nonce: <unique>`
       - Option B (App Auth): `X-App-Secret: <shared>` OR `X-App-Token: <app-jwt>`
     - Versioning: `X-API-Version: 1.0` or `1.1` (default = `1.0` if absent)
   - Response 200:
     ```json
     {
       "greeting": "Hello, Alice <alice@example.com>",
       "version": "1.0"
     }
     ```
     For version 1.1: timestamp appended in greeting.
   - Error responses: JSON `{ "error": "<reason>" }`

2. `OPTIONS /hello`
   - CORS/Preflight support
   - Returns `204 No Content`

### 7.2 Authentication Matrix
| Mode | Headers | Validation Path |
|------|---------|-----------------|
| User JWT | `Authorization: Bearer ...`, `X-Nonce` | JWKS fetch → JWT claims → nonce uniqueness |
| App Secret | `X-App-Secret` | Constant-time string compare |
| App JWT | `X-App-Token` | Decoded with `app_pub.pem` → issuer/aud/app_id/exp |

Priority: User JWT path attempted first; fallback to app auth.

---

## 8. API Versioning
- Header: `X-API-Version`
- Allowed: `1.0`, `1.1`
- Validation:
  - Format: digits '.' digits (exactly one dot)
  - Whitespace trimmed
  - Length capped (`MAX_API_VERSION_LEN`)
- Behavioral Difference:
  - `1.0`: basic greeting
  - `1.1`: greeting includes timestamp (`time_t`)
- Future versions must be added to `supported_versions[]`

---

## 9. Data Persistence
- File: `users.bin` (configurable)
- Structure: Fixed-size record (`User` struct) written atomically
- Locking: Exclusive file lock during append
- Append-only (no update or indexing)
- Binary format (not self-describing); future migration may require version tag

---

## 10. Key Structures

### ProviderEntry
Caching metadata for each auth provider issuer:
```
iss, jwks_url, expected_aud, current_kid, pubkey_pem, last_refresh, ttl
```
Protected by per-entry mutex.

### RateLimitEntry
Per-IP rolling window counter:
```
ip, request_count, window_start
```

### NonceEntry
Replay protection entry:
```
nonce (string), timestamp
```

### connection_info_struct
Per-request ephemeral state:
```
name/email buffers, accumulated POST size, client_ip, api_version,
postprocessor, authentication state
```

---

## 11. Threading Model
- libmicrohttpd started with `MHD_USE_THREAD_PER_CONNECTION`
- Background maintenance thread:
  - Sleeps `CLEANUP_INTERVAL_SECONDS`
  - Cleans nonce + rate-limit tables
  - Logs summary counts
- Shared mutable areas protected by:
  - `pthread_mutex_t` per provider (for key refresh)
  - Global locks for rate limit table, nonce table, config toggling, public key updates

---

## 12. JWKS Handling
1. Initial provider load: `init_providers_from_config()`
2. On decode:
   - Parse token header → `kid`
   - Lookup issuer (normalized)
   - Attempt verify with cached PEM
   - On failure → `refresh_provider()`:
     - Download JWKS JSON
     - Optional TTL from `Cache-Control`
     - Match `kid` or fallback to first RSA key
3. Store PEM in memory (not persisted to disk)

Failure cases logged with issuer, kid, audience for forensic traces.

---

## 13. Input Validation Logic
| Field | Max Length | Allowed Chars | Rejects |
|-------|-----------:|---------------|---------|
| name  | 48         | Alnum, space, `- _ .` | `< > " '` and others |
| email | 96         | Alnum, `. @ - _ +` | Structural invalid (`@`/`.` ordering) |
| nonce | < 64       | Arbitrary (length-enforced) | Empty / reused / oversize |
| Body  | 4096 bytes (global) | Aggregate guard | Early abort |

POST data processed incrementally via `MHD_PostProcessor`.

---

## 14. Logging
- Verbosity gate: `LOG_LEVEL`
- `[VERBOSE]` for trace (set LOG_LEVEL=1)
- `[ERROR]` for failures (always visible)
- JWT outcomes logged: `iss`, `kid`, `aud`, and success/failure
- Periodic cleanup metrics printed

Recommendation: Replace `fprintf(stderr, ...)` with structured JSON or syslog sink in production.

---

## 15. Error Responses
All application-level failures return:
```
HTTP <status>
Content-Type: application/json

{ "error": "<human-readable reason>" }
```
Examples:
- 400 Bad Request: invalid API version, invalid field
- 401 Unauthorized: missing/invalid token or nonce
- 413 Payload Too Large: aggregate POST > limit
- 404 Not Found: wrong path/method
- 429 Too Many Requests: rate limit
- 500 Internal Server Error: persistence or unexpected internal failure

---

## 16. Security Headers Added
| Header | Purpose |
|--------|---------|
| X-Content-Type-Options: nosniff | MIME sniff protection |
| X-Frame-Options: DENY | Clickjacking defense |
| Strict-Transport-Security | Enforce HTTPS (preload ready) |
| Access-Control-Allow-Origin | CORS restriction (static domain) |
| Cache-Control: no-store | Avoid caching responses (auth data) |
| Referrer-Policy: no-referrer | Privacy |
| Permissions-Policy | Limit browser feature exposure |

Preflight (OPTIONS) adds allowed methods & headers.

---

## 17. Dynamic Reload
Trigger: SIGHUP (POSIX) / Ctrl+Break (Windows simulation)
- Re-parses `config.json`
- Rebuilds providers map
- Re-applies server parameter globals
- Does not restart listener
Limitations: Active connections continue with old settings until completion.

---

## 18. Resource Management & Cleanup
Upon shutdown:
- Stops daemon
- Cancels background thread (if necessary)
- Frees:
  - Rate limit table
  - Nonce table
  - Provider map
  - Loaded PEM buffers
  - Config-derived strings
- Calls `curl_global_cleanup()`

---

## 19. Extensibility Points
| Area | Strategy |
|------|----------|
| Additional endpoints | Add branch in `answer_to_connection()` before error fallback |
| New API version | Append to `supported_versions[]`, implement branch logic |
| Alternative auth (e.g., mTLS) | Extend auth section in `check_oauth_bearer()` |
| Structured logging | Wrap macros or add JSON logger |
| Persistence | Replace `save_user()` with DB / queue producer |
| Observability | Insert metrics export (Prometheus text endpoint) |

---

## 20. Potential Improvements / TODO
1. Replace static global state with context struct passed to handlers
2. Implement exponential backoff on JWKS fetch failure
3. Harden email validation with RFC 5322 subset regex
4. Add configurable CORS origin allowlist
5. Memory pool allocator to reduce fragmentation under load
6. Optional auditing log channel (append-only)
7. Add health check endpoint (`GET /health`)
8. Support structured config validation with schema
9. Optional ECDSA (P-256) key support in JWKS
10. Pluggable rate limit strategies (token bucket / leaky bucket)

---

## 21. Known Limitations
- Single-process; no clustering / shared memory for rate limits
- Rate limiting & nonce tables in-memory only (lost on restart)
- `users.bin` grows indefinitely (no rotation)
- No outbound proxy support for JWKS fetch
- No DoS mitigation on rapid failed auth beyond rate limit
- No JIT re-verification of stale JWT mid-connection (one-shot per request design)

---

## 22. Hardening Recommendations
| Concern | Recommendation |
|---------|---------------|
| Secrets in config | Load from environment / secret manager |
| Memory disclosure | Compile with ASLR, stack protector, FORTIFY_SOURCE |
| Brute-force replay | Shorten nonce retention window or tie to token hash |
| Logging PII | Redact `email` in production logs or hash it |
| TLS Keys | Move default PEM paths to configurable, enforce file perms |
| Supply chain | Pin versions of libmicrohttpd, OpenSSL, jansson, libjwt |
| Build flags | Use `-fstack-protector-strong -D_FORTIFY_SOURCE=2 -O2 -pipe -fPIE -pie -Wl,-z,relro,-z,now` |
| Fuzzing | Integrate libFuzzer harness for `iterate_post`, JWT parsing |
| Testing | Add unit tests for validation functions & JWKS refresh state machine |

---

## 23. Function Grouping (Selected Highlights)
| Category | Functions |
|----------|-----------|
| Config | `load_config`, `reload_config`, `init_providers_from_config` |
| JWKS | `fetch_jwks`, `refresh_provider`, `convert_jwk_to_pem`, `normalize_iss` |
| Auth | `validate_jwt_user`, `validate_app`, `check_oauth_bearer`, `validate_nonce` |
| Security Helpers | `add_security_headers`, `parse_api_version`, `is_valid_email`, `is_valid_name` |
| Rate Limiting | `check_rate_limit`, `cleanup_expired_entries` |
| Persistence | `save_user`, `open_user_file`, `lock_file`, `unlock_file` |
| Request Handling | `answer_to_connection`, `iterate_post`, `request_completed` |
| Maintenance | `cleanup_thread_func`, `cleanup_nonce_table` |
| Shutdown | Signal handlers, final cleanup in `main` |

---

## 24. Example Usage

User JWT flow:
```bash
curl -k -X POST \
  -H "Authorization: Bearer <JWT>" \
  -H "X-Nonce: $(uuidgen)" \
  -H "X-API-Version: 1.1" \
  -d "name=Terry&email=terry@example.com" \
  https://127.0.0.1:8443/hello
```

App secret fallback:
```bash
curl -k -X POST \
  -H "X-App-Secret: replace_with_secure_random_value" \
  -H "X-API-Version: 1.0" \
  -d "name=ServiceBot&email=bot@example.com" \
  https://127.0.0.1:8443/hello
```

---

## 25. Glossary
| Term | Definition |
|------|------------|
| JWKS | JSON Web Key Set: published key set for JWT signature verification |
| KID | Key Identifier in JWT header selecting a key from JWKS |
| Nonce | One-time unique token to prevent replay |
| Audience (aud) | Intended recipient identifier in JWT |
| IAT | Issued-At timestamp claim |
| TTL | Time-to-live for cached JWKS-derived public key |

---

## 26. Quick Reference Summary
| Aspect | Value |
|--------|-------|
| Primary Endpoint | POST /hello |
| Auth Methods | User JWT (Bearer) + Nonce, App Secret, App JWT |
| Versions Supported | 1.0, 1.1 |
| Max Body Size | 4096 bytes |
| Rate Limit Default | 30 req/min/IP |
| Replay Window | ±300s (iat) + nonce table |
| Config Reload | SIGHUP / Ctrl+Break |
| Persisted File | users.bin (binary) |
| JWKS Refresh | TTL or `jwks_refresh_interval` fallback |

---

## 27. Change Integration Guidelines
When adding new features:
1. Update config schema & defaults
2. Extend documentation section (this file) accordingly
3. Add validation & tests
4. Ensure secure defaults (deny-by-default)
5. Maintain consistent logging format

---

## 28. Appendix: Risk-Oriented Checklist
| Check | Status |
|-------|--------|
| Input length bounds | Implemented |
| Format validation (email/version) | Implemented (basic) |
| JWT exp & iat verified | Yes |
| Replay via nonce & iat | Yes |
| Symlink file attack | Mitigated with `O_NOFOLLOW` |
| Race on shared state | Mutex-protected |
| TLS enforced | Yes (server only runs in HTTPS mode) |
| Config reload safety | Mutex + rebuild |
| Crash on large POST | Prevented (body cap + early abort) |
| Logging secrets | Avoids printing tokens (OK) |

---

If you need this converted into a `README.md` or split into smaller docs (e.g., SECURITY.md, ARCHITECTURE.md), let me know and I can generate those variants.
