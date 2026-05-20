# Doppel

Transparent TLS identity proxy for local automation, security testing, and
network-fingerprint research.

[![CI](https://github.com/redstone-md/Doppel/actions/workflows/ci.yml/badge.svg)](https://github.com/redstone-md/Doppel/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/redstone-md/Doppel.svg)](https://pkg.go.dev/github.com/redstone-md/Doppel)
[![License: PolyForm Noncommercial 1.0.0](https://img.shields.io/badge/license-PolyForm%20Noncommercial%201.0.0-blue.svg)](LICENSE)

Doppel runs as a local HTTP CONNECT and SOCKS5 proxy. Your application connects
to Doppel instead of connecting directly to the public internet. Doppel
terminates the client-side TLS connection with a locally generated certificate
authority, then opens a fresh upstream TLS connection using a browser-like
fingerprint selected from a profile.

The result is a coherent transport identity: TLS ClientHello, ALPN, User-Agent,
common browser headers, and HTTP/1.1 header ordering are applied from the same
profile instead of being mixed by accident.

## License and commercial use

Doppel is source-available under the
[PolyForm Noncommercial License 1.0.0](LICENSE). You may use, study, modify, and
redistribute it for non-commercial purposes allowed by that license.

Commercial use is not permitted unless you receive a separate written license
from the project maintainers. This includes embedding Doppel in a paid product,
using it to provide a paid service, or using it inside commercial operations.

## Intended use

Doppel is intended for authorised work only:

- Testing WAF, bot-detection, anti-fraud, or API-gateway controls that you own
  or are explicitly authorised to assess.
- Reproducing client-fingerprint issues in development and staging
  environments.
- Security research, protocol research, and non-commercial automation against
  systems where you have permission.
- Building internal experiments that need consistent browser-like TLS and
  header behaviour.

Doppel is not a browser, does not solve JavaScript challenges, does not improve
IP reputation, and does not grant permission to access any third-party system.
You are responsible for complying with law, contracts, robots policies, and the
terms of services you interact with.

## How it works

```text
your app / scraper / CLI / agent
        |
        |  SOCKS5 or HTTP CONNECT
        v
  Doppel local proxy
        |
        |  1. accepts the client connection
        |  2. terminates TLS with a machine-local CA
        |  3. rewrites headers from the selected profile
        |  4. opens upstream TLS with a uTLS ClientHello
        v
target server sees the selected profile's network identity
```

Because Doppel decrypts and re-encrypts traffic, each client that uses it must
trust Doppel's local CA certificate. The CA is generated on your machine by
`doppel init`; it is not bundled with the repository or releases.

## What Doppel does and does not do

| Layer | Status |
| --- | --- |
| TLS fingerprint, including JA3 / JA4 shape | Supported via uTLS |
| Browser-like User-Agent and request headers | Supported |
| HTTP/1.1 header order | Supported |
| HTTP/2 connection fingerprint | Partial; Go's HTTP/2 stack is still visible |
| TCP/IP stack fingerprint | Not supported; this is controlled by the host OS |
| Browser JavaScript, DOM, canvas, WebGL, cookies | Not supported |
| CAPTCHA or challenge solving | Not supported |
| IP reputation or residential egress | Not supported |
| Behavioural modelling | Not supported |

Consistency matters. A Safari TLS fingerprint with a Python User-Agent is more
suspicious than a normal automation client. Use one profile as a complete
identity and avoid overriding individual pieces unless you know the downstream
effect.

## Install

Requires Go 1.23 or newer.

```sh
go install github.com/redstone-md/Doppel/cmd/doppel@latest
```

Build from source:

```sh
git clone https://github.com/redstone-md/Doppel.git
cd Doppel
go build -o doppel ./cmd/doppel
```

For reproducible local builds, the Makefile wraps the common commands:

```sh
make build
make check
```

## Quick start

Generate a local CA and follow the printed trust-store instructions:

```sh
doppel init
```

Start the proxy with a built-in profile:

```sh
doppel run --profile iphone15-safari
```

Point a client at Doppel:

```sh
export HTTPS_PROXY=socks5://127.0.0.1:8080
curl https://example.com
```

On Windows, PowerShell syntax is:

```powershell
$env:HTTPS_PROXY = "socks5://127.0.0.1:8080"
curl.exe https://example.com
```

Verify the upstream fingerprint path without running the proxy:

```sh
doppel verify --profile iphone15-safari
```

The `verify` command fetches a fingerprint-reporting endpoint and prints what
the server observed:

```text
profile : iphone15-safari
url     : https://get.ja3.zone/
status  : 200 OK
protocol: HTTP/2.0
---
{ ... fingerprint report ... }
```

## Commands

| Command | Purpose |
| --- | --- |
| `doppel init` | Generate or reuse the local CA and print setup guidance |
| `doppel run` | Start the local proxy |
| `doppel launch` | Start Doppel and run one application through it |
| `doppel profiles` | List built-in and user-supplied identity profiles |
| `doppel ca` | Show or export the local CA certificate |
| `doppel verify` | Check the selected profile against a remote endpoint |
| `doppel version` | Print the CLI version |

Run `doppel <command> -h` for command-specific flags.

Useful flags:

| Flag | Commands | Purpose |
| --- | --- | --- |
| `--profile <name>` | `run`, `launch`, `verify` | Select the identity profile |
| `--addr <host:port>` | `init`, `run`, `launch` | Change the proxy address; default is `127.0.0.1:8080` |
| `--data <path>` | `init`, `run`, `launch`, `profiles`, `ca`, `verify` | Use a custom data directory |
| `--force` | `init` | Regenerate the local CA |
| `--export <path>` | `ca` | Write the CA certificate to a file |
| `--insecure` | `run`, `launch` | Skip upstream certificate verification for debugging only |
| `--upstream-proxy <url>` | `run`, `launch`, `verify` | Route Doppel egress through a SOCKS5 proxy |
| `-v` | `run`, `launch` | Enable debug logging |
| `--electron` | `launch` | Add Chromium/Electron proxy switches to the child process |

## Built-in profiles

A profile is a complete network identity: TLS ClientHello template, ALPN list,
User-Agent, browser headers, header order, and planned HTTP/2 traits.

| Name | Device identity |
| --- | --- |
| `iphone15-safari` | iPhone 15 Pro, iOS 17, Mobile Safari |
| `chrome-android` | Chrome 131 on Android 14, Pixel 8 |
| `chrome-windows` | Chrome 131 on Windows 11 |
| `firefox-windows` | Firefox 133 on Windows 11 |
| `safari-macos` | Safari 17 on macOS Sonoma |

List profiles available on your machine:

```sh
doppel profiles
```

## Custom profiles

Custom profiles are JSON files stored in the user profiles directory. Use
`doppel ca` to see the active data directory, then create a `profiles`
subdirectory inside it. A custom profile with the same name as a built-in one
overrides the built-in profile.

Minimal profile example:

```json
{
  "name": "my-device",
  "description": "Example custom browser identity",
  "client_hello": "chrome",
  "user_agent": "Mozilla/5.0 ...",
  "alpn": ["h2", "http/1.1"],
  "headers": {
    "order": ["host", "connection", "user-agent", "accept", "accept-language"],
    "set": {
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Language": "en-US,en;q=0.9"
    }
  }
}
```

Supported `client_hello` templates are `chrome`, `firefox`, `safari`,
`safari-ios`, `edge`, and `randomized`.

## Usage examples

### Route Doppel through an upstream SOCKS5 proxy

Use `--upstream-proxy` when Doppel itself should egress through another proxy:

```sh
doppel verify --upstream-proxy socks5://user:pass@proxy.example:1080
```

The same value can be supplied with `DOPPEL_UPSTREAM_PROXY` for `run`, `launch`,
and `verify`. Provider-style `socks5://host:port:user:pass` URLs are accepted.

### Launch an app through Doppel

`doppel launch` starts a temporary Doppel proxy, launches one child process with
HTTPS proxy environment variables, and stops the proxy when the child exits:

```sh
doppel launch --profile chrome-windows -- curl https://example.com
```

For Electron or Chromium-based desktop apps, add `--electron`. Doppel appends
Chromium proxy switches so the app does not need proxychains or LD_PRELOAD:

```sh
doppel launch --profile chrome-windows --electron -- /path/to/electron-app
```

By default the Chromium switch proxies HTTPS URLs only, because Doppel expects a
TLS stream after CONNECT. See [Launching applications](docs/LAUNCHING_APPS.md)
for Windows, macOS, Linux, and Electron notes.

### curl

```sh
doppel run --profile chrome-windows
curl --proxy socks5h://127.0.0.1:8080 https://example.com
```

If curl on Windows uses Schannel and rejects the local CA because of revocation
checks, add `--ssl-no-revoke`.

### Python requests

Install SOCKS support:

```sh
python -m pip install "requests[socks]"
```

Then route traffic through Doppel and trust the exported CA certificate:

```python
import requests

proxies = {
    "http": "socks5h://127.0.0.1:8080",
    "https": "socks5h://127.0.0.1:8080",
}

response = requests.get(
    "https://example.com",
    proxies=proxies,
    verify="/path/to/doppel-ca.pem",
    timeout=30,
)
print(response.status_code)
print(response.text[:200])
```

Export the CA with:

```sh
doppel ca --export ./doppel-ca.pem
```

### Go HTTP client

```go
package main

import (
    "crypto/tls"
    "crypto/x509"
    "fmt"
    "net/http"
    "net/url"
    "os"
    "time"
)

func main() {
    proxyURL, err := url.Parse("http://127.0.0.1:8080")
    if err != nil {
        panic(err)
    }

    caPEM, err := os.ReadFile("./doppel-ca.pem")
    if err != nil {
        panic(err)
    }
    roots := x509.NewCertPool()
    if !roots.AppendCertsFromPEM(caPEM) {
        panic("failed to load Doppel CA")
    }

    transport := &http.Transport{
        Proxy: http.ProxyURL(proxyURL),
        TLSClientConfig: &tls.Config{RootCAs: roots},
    }

    client := &http.Client{
        Transport: transport,
        Timeout:   30 * time.Second,
    }

    resp, err := client.Get("https://example.com")
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()
    fmt.Println(resp.Status)
}
```

## Product integration guidance

For non-commercial products or authorised internal tooling, treat Doppel as an
external local service rather than a library embedded into your process:

- Run one Doppel process per host or per isolated workload.
- Generate a separate CA per environment. Never share a development CA with CI,
  staging, production, or another developer.
- Keep the proxy bound to localhost unless there is a deliberate network
  isolation boundary in front of it.
- Prefer profile-level changes over per-request header overrides.
- Log profile name, target host, and status codes. Do not log request bodies,
  secrets, cookies, bearer tokens, or full URLs containing credentials.
- Rotate the CA when a machine is reassigned or when the key may have been
  copied.

Doppel's current Go packages live under `internal/`, so they are intentionally
not a public library API. The supported integration surface is the CLI and the
local proxy protocol.

## Security model

The local CA is powerful. Anyone with the generated private key can sign
certificates for any host trusted by clients that installed the CA.

- The CA is generated per machine and stored in the Doppel data directory.
- The private key must never be committed, uploaded, copied to another host, or
  shipped in a container image.
- The default proxy bind address is `127.0.0.1:8080` to avoid exposing the proxy
  to the network by accident.
- Doppel verifies upstream certificates by default. Use `--insecure` only in a
  controlled debugging environment.
- Remove the CA from all OS and language-runtime trust stores when uninstalling
  Doppel.

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## Troubleshooting

### `doppel run` says no CA was found

Run `doppel init` first, or pass the same `--data` directory that was used when
the CA was generated.

### The client still rejects the certificate

The client process does not trust Doppel's CA. Some runtimes ignore the OS trust
store and need explicit configuration. Export the CA with `doppel ca --export`
and configure the runtime or HTTP library to trust that certificate.

### A target still blocks the request

Doppel changes transport-level and header-level signals only. It cannot solve
JavaScript challenges, repair IP reputation, execute browser APIs, or make
unauthorised access acceptable.

### `doppel verify` shows an unexpected HTTP/2 fingerprint

Expected for now. TLS ClientHello selection is profile-controlled, but exact
HTTP/2 SETTINGS and pseudo-header ordering are still on the roadmap.

## Architecture

```text
cmd/doppel        CLI entry point
internal/ca       local CA generation, loading, and leaf certificate minting
internal/config   runtime paths and defaults
internal/mitm     TLS termination and request re-origination
internal/profile  profile schema, validation, built-in profiles
internal/proxy    single-port SOCKS5 and HTTP CONNECT listener
internal/upstream uTLS dialer, HTTP round tripper, response decoding
internal/wizard   first-run setup guidance
```

The implementation keeps profile data separate from TLS mechanics: profiles are
validated as pure data, while `internal/upstream` maps them onto uTLS and HTTP
transport behaviour. This keeps profile authoring independent from proxy and CA
state.

## Roadmap

- Exact HTTP/2 fingerprint control, including SETTINGS frames and pseudo-header
  order.
- Version-pinned ClientHello specs for each built-in profile.
- Realistic mutation within a profile's normal browser envelope.
- Idle timeout controls for long-lived keep-alive client connections.
- Release artifacts for common operating systems.

## Development

Before opening a pull request, run:

```sh
go build ./...
go vet ./...
go test ./...
gofmt -l .
```

Or run the combined Make target on systems with `make`:

```sh
make check
```

Do not commit machine-local data. In particular, never commit `data/`, CA
private keys, `.env` files, local agent state, request logs, cookies, or tokens.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

[PolyForm Noncommercial License 1.0.0](LICENSE). Commercial use requires a
separate written license.
