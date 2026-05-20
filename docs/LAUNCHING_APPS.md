# Launching Applications Through Doppel

`doppel launch` is the recommended way to run a single application through
Doppel without proxychains-ng, LD_PRELOAD, or global OS proxy changes.

It starts Doppel, launches the child process with proxy-related environment
variables, and stops Doppel when the child process exits.

## Basic usage

Initialize the local CA once:

```sh
doppel init
```

Launch an application:

```sh
doppel launch --profile chrome-windows -- <command> [args...]
```

Example with curl:

```sh
doppel launch --profile chrome-windows -- curl https://example.com
```

The `--` separator matters when the child command has its own flags.

## What the launcher sets

By default, `doppel launch` sets HTTPS-oriented environment variables for the
child process:

```text
HTTPS_PROXY=http://127.0.0.1:8080
https_proxy=http://127.0.0.1:8080
NO_PROXY=localhost,127.0.0.1,::1
no_proxy=localhost,127.0.0.1,::1
REQUESTS_CA_BUNDLE=<doppel ca.pem>
NODE_EXTRA_CA_CERTS=<doppel ca.pem>
SSL_CERT_FILE=<doppel ca.pem>
```

`HTTP_PROXY`, `http_proxy`, `ALL_PROXY`, and `all_proxy` are removed from the
child environment. Doppel is a TLS identity proxy and expects CONNECT/SOCKS5
followed by a TLS stream. Plain HTTP forwarding is not part of the current
design.

## Upstream SOCKS5 egress

`doppel launch` can also route Doppel's outbound side through a SOCKS5 proxy:

```sh
doppel launch --upstream-proxy socks5://user:pass@proxy.example:1080 -- \
  curl https://example.com
```

The child application still talks only to local Doppel. The upstream proxy URL
is consumed by Doppel and should be provided through a secret manager or
short-lived environment variable in automation.

## Electron and Chromium apps

Electron applications are Chromium-based, so environment variables are often
not enough. Use `--electron` to append Chromium proxy switches to the launched
process:

```sh
doppel launch --profile chrome-windows --electron -- /path/to/electron-app
```

The launcher appends:

```text
--proxy-server=https=http://127.0.0.1:8080
--proxy-bypass-list=<local>
```

The HTTPS-only proxy rule is deliberate: Doppel handles HTTPS requests where the
client opens a CONNECT tunnel and then starts TLS. If you need to force Chromium
to send all URL schemes to Doppel for debugging, add `--all-schemes`, but plain
HTTP requests will not be rewritten into TLS and may fail.

```sh
doppel launch --electron --all-schemes -- /path/to/electron-app
```

For Electron applications you control, the equivalent in the main process is:

```js
const { app } = require('electron')

app.commandLine.appendSwitch('proxy-server', 'https=http://127.0.0.1:8080')
app.commandLine.appendSwitch('proxy-bypass-list', '<local>')
```

Append these switches before `app.whenReady()`.

## Windows examples

PowerShell:

```powershell
doppel launch --profile chrome-windows --electron -- "C:\Users\you\AppData\Local\Programs\App\App.exe"
```

If the launched app is not Electron/Chromium-based, omit `--electron`:

```powershell
doppel launch --profile chrome-windows -- python .\client.py
```

## macOS examples

Electron `.app` bundles usually need the real executable inside the bundle:

```sh
doppel launch --electron -- \
  "/Applications/Example.app/Contents/MacOS/Example"
```

## Linux examples

```sh
doppel launch --electron -- /usr/bin/example-app
```

For AppImage builds:

```sh
doppel launch --electron -- ./Example.AppImage
```

## When to still use system proxy settings

Some closed-source desktop apps sanitize command-line arguments or spawn helper
processes without inheriting the parent environment. For those apps, use OS
proxy settings or the app's own proxy settings and point HTTPS traffic at
`127.0.0.1:8080`.

System proxy mode is broader than `doppel launch`, so use it carefully and turn
it off after the test. `doppel launch` is preferred when you want one target app
without affecting the rest of the machine.

## Known limits

- Doppel handles HTTPS/TLS traffic, not arbitrary TCP protocols.
- Plain HTTP URLs are not converted to HTTPS.
- Apps with certificate pinning may reject Doppel's generated leaf
  certificates even after the CA is trusted.
- Electron apps that ignore Chromium command-line switches need in-app proxy
  configuration or OS proxy settings.
- Child processes that drop inherited environment variables may need explicit
  app-level proxy configuration.
