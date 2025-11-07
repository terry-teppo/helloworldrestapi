# Hello World Cross-Platform JWT REST API (C)

This project is a **secure, production-ready, cross-platform REST API server written in C**, designed to demonstrate best practices for authentication, config management, and portability. It emphasizes security, maintainability, and standards compliance.

## Features

- **Cross-Platform**: Runs on Linux, macOS, and Windows with minimal changes.
- **JWT & JWKS Support**: Validates JSON Web Tokens using live keys from multiple providers (Google, Microsoft, Auth0, Okta, Apple).
- **Dynamic Config**: Reload `config.json` on the fly (SIGHUP on POSIX, Ctrl+Break on Windows) without server restart.
- **Strong Security**: Rate limiting, nonce replay protection, structured logging, and security headers.
- **API Versioning**: Accepts API version via HTTP headers for forward compatibility.
- **Thread-Safe**: Handles concurrency, provider map, and cleanup.
- **No Recompilation for Most Changes**: Change providers/secrets/limits via config, not code.

## Build

- **Linux**:  
  `gcc -o server hello.c -lcurl -lssl -lcrypto -ljansson -pthread`
- **macOS**:  
  `clang -o server hello.c -lcurl -lssl -lcrypto -ljansson`
- **Windows**:  
  `cl hello.c /link ws2_32.lib User32.lib Advapi32.lib Crypt32.lib`  
  _or_  
  `x86_64-w64-mingw32-gcc hello.c -o server.exe -lcurl -lssl -lcrypto -ljansson -pthread`

_Ensure dependencies: `libmicrohttpd`, `jansson`, `libcurl`, `openssl`, `libjwt`, `uthash`._

## Usage

1. Edit `config.json` to define your server, keys, and JWT providers.
2. Run: `./server`  
   The server will listen on the port configured in `config.json` (default 8443, HTTPS).
3. API usage example:

   ```
   curl -k -X POST \
        -H "Authorization: Bearer <JWT>" \
        -H "X-Nonce: <unique-nonce>" \
        -H "X-API-Version: 1.1" \
        -d "name=Terry&email=terry@example.com" \
        https://localhost:8443/hello
   ```

4. To reload the config at runtime:
   - On Linux/macOS: `kill -HUP <pid>`
   - On Windows: Press `Ctrl+Break` in the server console

## Maintainer

[terry-teppo](https://github.com/terry-teppo) • terry-teppo@users.noreply.github.com

## Security Notes

- Always use real, strong secrets and keys in production.
- Configure HTTPS certificates and set minimal file permissions for your keys and config files.

## Example `config.json`

See the included `config.json` for an example with multiple JWT providers.

## License

[MIT](LICENSE)
