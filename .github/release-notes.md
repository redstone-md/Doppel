# Doppel Release

## Install

Download the archive for your operating system and CPU from the assets below,
then put the `doppel` binary somewhere on your `PATH`.

Linux and macOS:

```sh
tar -xzf doppel_<version>_<os>_<arch>.tar.gz
cd doppel_<version>_<os>_<arch>
chmod +x doppel
./doppel version
```

Windows PowerShell:

```powershell
Expand-Archive .\doppel_<version>_windows_amd64.zip
.\doppel_<version>_windows_amd64\doppel.exe version
```

## First run

Generate a machine-local CA and follow the printed trust-store instructions:

```sh
doppel init
```

Start the proxy:

```sh
doppel run --profile safari-ios-iphone15
```

Point an HTTPS client at Doppel:

```sh
HTTPS_PROXY=http://127.0.0.1:8080 curl https://example.com
```

Run one app through Doppel without changing global proxy settings:

```sh
doppel launch --profile chrome-win11 -- curl https://example.com
```

Electron or Chromium apps:

```sh
doppel launch --profile chrome-win11 --electron -- /path/to/app
```

Optional upstream SOCKS5 egress:

```sh
doppel verify --upstream-proxy socks5://user:pass@proxy.example:1080
```

Commercial use is not permitted under the default license. See `LICENSE`.
