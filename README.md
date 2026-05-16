# Doppel

**Transparent TLS identity proxy.** Point any HTTP client at Doppel and its
traffic leaves the machine wearing the TLS fingerprint of a different device.

[![CI](https://github.com/Rxflex/doppel/actions/workflows/ci.yml/badge.svg)](https://github.com/Rxflex/doppel/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/Rxflex/doppel.svg)](https://pkg.go.dev/github.com/Rxflex/doppel)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

---

## What it is

Modern anti-bot systems do not only read *what* a client requests — they read
*how* it requests it. The TLS `ClientHello` a program sends has a measurable
shape (its **JA3 / JA4** fingerprint), and a lightweight scraper, CLI tool or
AI agent is given away by that shape long before its first byte of HTTP.

Doppel sits between your program and the network as a local proxy. It
terminates the client's TLS, then re-originates the request to the real server
using a `ClientHello` copied from a real device — an iPhone, a Chrome desktop —
so the server sees a fingerprint that matches a genuine browser.

Your program needs no code changes. It points at the proxy; Doppel does the
rest.

## How it works

```
  ┌────────────┐   SOCKS5 / HTTP CONNECT   ┌──────────────────────────┐
  │  your app  │ ────────────────────────► │          Doppel          │
  │  scraper / │                           │                          │
  │  CLI / AI  │ ◄──────────────────────── │  1. terminate client TLS │
  │   agent    │      response to app      │     with local CA cert   │
  └────────────┘                           │  2. rewrite headers to   │
                                           │     match the profile    │
                                           │  3. re-originate upstream│
                                           │     with a uTLS hello    │
                                           └────────────┬─────────────┘
                                                        │  ClientHello =
                                                        │  chosen profile
                                                        ▼
                                                 ┌──────────────┐
                                                 │    server    │
                                                 │  sees a real │
                                                 │  device JA3  │
                                                 └──────────────┘
```

To rewrite a TLS fingerprint, Doppel must decrypt and re-encrypt the stream.
That requires the client to trust a certificate authority Doppel generates
locally — the `doppel init` wizard walks you through it. The CA is unique to
each machine and never leaves it.

## What it does — and does not — do

A valid JA3/JA4 is necessary but not sufficient. Anti-bot systems score the
whole stack, and consistency across layers matters more than any single
signal. Be honest with yourself about which gate you are actually facing.

| Layer | Handled |
|---|---|
| TLS fingerprint (JA3 / JA4) | ✅ Yes — via [uTLS](https://github.com/refraction-networking/utls) |
| Request header values (User-Agent, client hints, `Accept-*`) | ✅ Yes |
| HTTP/1.1 header order | ✅ Yes |
| HTTP/2 fingerprint (Akamai: SETTINGS, header order) | ⚠️ Partial — see [Roadmap](#roadmap) |
| TCP/IP stack fingerprint | ❌ No — the host kernel's stack is unavoidable |
| JavaScript challenges (Cloudflare Turnstile, etc.) | ❌ No — needs a real browser engine |
| IP reputation | ❌ No — pair Doppel with an appropriate egress IP |
| Behavioural analysis (timing, navigation) | ❌ No — that is your client's responsibility |

> **Consistency is everything.** A perfect iPhone JA3 paired with a
> `python-requests` User-Agent is *more* suspicious than no spoofing at all —
> real iPhones never produce that combination. A profile is a single coherent
> identity; do not mix its parts.

## Install

Requires Go 1.23 or newer.

```sh
go install github.com/Rxflex/doppel/cmd/doppel@latest
```

Or build from source:

```sh
git clone https://github.com/Rxflex/doppel
cd doppel
go build -o doppel ./cmd/doppel
```

## Quick start

**1. Generate the local CA and follow the setup guide:**

```sh
doppel init
```

This prints the CA fingerprint and per-platform / per-runtime instructions for
trusting it. Language runtimes (Python, Node.js, Go) ship their own trust
stores and ignore the OS one, so the guide covers them separately.

**2. Start the proxy:**

```sh
doppel run --profile iphone15-safari
```

**3. Point your client at it:**

```sh
export HTTPS_PROXY=socks5://127.0.0.1:8080   # or http://127.0.0.1:8080
curl https://example.com
```

The same port serves both SOCKS5 and HTTP CONNECT — the protocol is detected
automatically.

**4. Confirm the fingerprint:**

```sh
doppel verify --profile iphone15-safari
```

`verify` fetches a fingerprint-reporting service and shows what the server
observed:

```
profile : iphone15-safari
status  : 200 OK
protocol: HTTP/2.0
---
{
  "ja3_hash": "656b9a2f4de6ed4909e157482860ab3d",
  "ja4": "t13d2613h2_2802a3db6c62_2f334c0ef380",
  "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) ..."
}
```

## Commands

| Command | Purpose |
|---|---|
| `doppel init` | Generate the local CA and print the setup guide |
| `doppel run` | Start the proxy |
| `doppel profiles` | List available identity profiles |
| `doppel ca` | Show or export the local CA certificate |
| `doppel verify` | Check the emulated fingerprint against a remote service |
| `doppel version` | Print the version |

Run `doppel <command> -h` for command-specific flags.

## Profiles

A profile is a complete, coherent network identity: a TLS `ClientHello`
template, ALPN list, User-Agent, header set and ordering. Built-in profiles:

| Name | Device |
|---|---|
| `iphone15-safari` | iPhone 15 Pro, iOS 17, Mobile Safari |
| `chrome-android` | Chrome 131 on Android 14 (Pixel 8) |
| `chrome-windows` | Chrome 131 on Windows 11 |
| `firefox-windows` | Firefox 133 on Windows 11 |
| `safari-macos` | Safari 17 on macOS Sonoma |

Custom profiles are JSON files dropped into the profiles directory
(`doppel ca` shows the data directory location). A profile that shares a name
with a built-in one overrides it.

```json
{
  "name": "my-device",
  "description": "Example custom profile",
  "client_hello": "chrome",
  "user_agent": "Mozilla/5.0 ...",
  "alpn": ["h2", "http/1.1"],
  "headers": {
    "order": ["host", "user-agent", "accept"],
    "set": { "Accept-Language": "en-US,en;q=0.9" }
  }
}
```

Supported `client_hello` templates: `chrome`, `firefox`, `safari`,
`safari-ios`, `edge`, `randomized`.

## Troubleshooting

**curl on Windows fails with a certificate error.** A curl built against
Schannel runs CRL/OCSP revocation checks that a private CA cannot satisfy.
Pass `--ssl-no-revoke`. Clients built on OpenSSL (most Python and CLI
tooling), BoringSSL (Node.js) or Go are unaffected.

**`doppel verify` reports an HTTP/2 fingerprint that is not the profile's.**
Expected: the upstream HTTP/2 layer is not yet fingerprint-controlled. The
TLS (JA3/JA4) fingerprint *is* the profile's. See the [Roadmap](#roadmap).

**A site still blocks the request.** Doppel changes the transport fingerprint
only. If the site serves a JavaScript challenge or scores your egress IP, no
TLS profile will help — see [What it does](#what-it-does--and-does-not--do).

## Architecture

```
cmd/doppel            command-line interface
internal/ca           local certificate authority, on-demand leaf minting
internal/profile      identity profiles and built-in fingerprints
internal/upstream     uTLS dialer + HTTP/1.1 and HTTP/2 round tripper
internal/mitm         TLS termination and request re-origination
internal/proxy        SOCKS5 / HTTP CONNECT listener
internal/config       runtime paths and defaults
internal/wizard       first-run setup guidance
```

## Roadmap

- Exact HTTP/2 fingerprint control (SETTINGS frame, pseudo-header and header
  order) — currently the upstream HTTP/2 layer carries Go's own fingerprint.
- Pinned, version-exact `ClientHello` specs per profile, instead of uTLS
  "auto" templates.
- Dynamic mutation within a profile's realistic envelope.
- An idle timeout for long-lived keep-alive client connections.

Done since the initial cut: per-host HTTP/2 connection pooling, and
transparent gzip / brotli / zstd / deflate response decoding.

## Security

The CA Doppel generates can sign a certificate for any domain. Anyone holding
its private key can intercept TLS for every host the machine trusts.

- The CA is generated **per machine** and is never bundled into releases.
- The private key is written with owner-only permissions. Keep it that way.
- Never commit `ca.key` or copy it off the host.
- Remove the CA from every trust store when you uninstall Doppel.

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities.

## Intended use

Doppel is a tool for **authorised** work: testing your own anti-fraud and WAF
deployments, security research, and automation against services you own or
have permission to access. Using it to bypass access controls without
authorisation may be illegal. You are responsible for how you use it.

## Contributing

Issues and pull requests are welcome. Before submitting, run:

```sh
go build ./... && go vet ./... && go test ./... && gofmt -l .
```

## License

[MIT](LICENSE)
