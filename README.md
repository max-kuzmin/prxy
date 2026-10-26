# Prxy

Prxy is a lightweight, high-performance, multi-protocol proxy server written in .NET 10. It compiles via **Native AOT** into a self-contained, standalone native binary (~2.1 MB) that runs on any machine with **no .NET runtime or SDK installed**.

It listens on a single port and automatically detects the client protocol (**SOCKS5**, **SOCKS4**, **HTTP**, or **HTTPS/TLS**), routing traffic either directly to the destination or through an upstream proxy.

---

## Features

- **No Runtime Required**: Compiles to a single native binary (~2.1 MB) with Native AOT and size trimming optimizations. Runs on target systems without installing .NET.
- **Cross-Platform**: Works on Windows, Linux, and macOS.
- **Automatic Protocol Recognition**: Accepts and detects SOCKS5, SOCKS4, HTTP (`CONNECT` and standard HTTP verbs), and HTTPS (transparent TLS SNI routing) on the same listening port.
- **Upstream Forwarding**: Supports chaining through upstream proxies via `http://`, `https://`, `socks4://`, or `socks5://` with optional basic authentication.
- **Inbound Authentication**: Protects the proxy with `--auth <user:pass>` using HTTP `407 Proxy Authentication Required` and SOCKS5 RFC 1929 credentials.
- **Address Binding**: Restricts access with `--bind <address>` (e.g. `127.0.0.1` for local-only, or `0.0.0.0` for all interfaces).
- **Rich Request Logging**: Formatted logging showing HTTP/SOCKS method, target URL, status, and payload response size (`[CONNECT] https://example.com:443 -> 200 (5.7 KB)`).
- **Configurable Timeout**: Connection and handshake timeout (default: 60 seconds).
- **Zero-Config Default**: Running without arguments starts immediately on default port **`8889`**.
- **Graceful Shutdown**: Intercepts `Ctrl+C` for clean socket and stream termination.

---

## Command-Line Arguments

| Flag | Type | Default | Description |
|---|---|---|---|
| `--port <number>` | integer | `8889` | Port number on which the proxy listens. |
| `--bind <address>` | string | `0.0.0.0` | IP address to bind to (`127.0.0.1` for localhost-only). |
| `--auth <user:pass>` | string | _None_ | Require incoming client authentication (Basic for HTTP, RFC 1929 for SOCKS5). |
| `--upstream <url>` | string | _None_ | Upstream proxy URL where all traffic is routed (e.g., `http://user:pass@host:port`). |
| `--log` | switch | `false` | Enables rich request logging (`[{Method}] {Url} -> {Status} ({Size})`). |
| `--insecure` | switch | `false` | Ignore all TLS/SSL certificate and validation errors. |
| `--timeout <seconds>` | integer | `60` | Inactivity/idle timeout in seconds. |
| `--help`, `-h` | switch | | Displays help and usage information. |

---

## Building Native Binaries (No .NET Required on Target Machine)

### Windows (x64)
```powershell
dotnet publish -c Release -r win-x64
```
Output: `bin\Release\net10.0\win-x64\publish\Prxy.exe` (~2.1 MB)

### Linux (x64)
```bash
dotnet publish -c Release -r linux-x64
```
Output: `bin/Release/net10.0/linux-x64/publish/Prxy`

### Linux (ARM64)
```bash
dotnet publish -c Release -r linux-arm64
```
Output: `bin/Release/net10.0/linux-arm64/publish/Prxy`

### macOS (Apple Silicon / ARM64)
```bash
dotnet publish -c Release -r osx-arm64
```
Output: `bin/Release/net10.0/osx-arm64/publish/Prxy`

---

## Quick Start

### 1. Run with Defaults
Starts immediately on port `8889` listening on all interfaces:
```powershell
./Prxy.exe
```

### 2. Localhost-Only with Logging
```powershell
./Prxy.exe --bind 127.0.0.1 --port 8889 --log
```

### 3. Run with Inbound Authentication
Require clients to authenticate with username and password:
```powershell
./Prxy.exe --port 8889 --auth myuser:secretpass --log
```

### 4. Run with Upstream Proxy Forwarding
Forward all incoming traffic through an authenticated upstream proxy:
```powershell
./Prxy.exe --port 8889 --upstream "http://username:password@11.22.33.44:9116" --log --timeout 30
```

---

## Client Usage Examples

Once the proxy is running on a port (e.g. `localhost:8889`):

### Standard HTTP Forward Proxy
```powershell
curl.exe -x http://localhost:8889 -I http://example.com
```

### HTTPS Tunneling (`CONNECT`)
```powershell
curl.exe -x http://localhost:8889 -I https://example.com
```

### Authenticated Proxy Request
```powershell
curl.exe -U myuser:secretpass -x http://localhost:8889 -I https://example.com
```

### Authenticated SOCKS5 Proxy
```powershell
curl.exe --socks5-hostname myuser:secretpass@localhost:8889 -I https://example.com
```

### SOCKS4 Proxy
```powershell
curl.exe --socks4a localhost:8889 -I http://example.com
```
