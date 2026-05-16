# Security Policy

## The local CA is sensitive

Doppel works by terminating TLS, which requires a certificate authority the
client trusts. That CA can sign a certificate for **any** domain. Whoever
holds its private key can intercept TLS for every host the machine trusts.

Treat `ca.key` like a password:

- It is generated per machine and written with owner-only permissions.
- Never commit it, copy it to another host, or store it in a shared location.
- A CA is never embedded in a Doppel release. If a build ships with a
  pre-generated CA, do not use it.
- When uninstalling Doppel, remove the CA from every trust store you added it
  to (OS store and any language runtimes) and delete the key.

## Upstream verification

Doppel verifies the certificate of the real upstream server by default.
The `--insecure` flag disables this and exists only for debugging. Running the
proxy with `--insecure` outside a controlled environment exposes traffic to a
genuine man-in-the-middle.

## Reporting a vulnerability

Please report security issues privately rather than opening a public issue.
Open a [GitHub security advisory](https://github.com/Rxflex/doppel/security/advisories/new)
or contact the maintainers directly.

Include the affected version, reproduction steps, and the impact you observed.
We aim to acknowledge reports within a few days.
