// Package wizard renders the first-run guidance shown after the local CA is
// generated.
//
// Trusting the CA in the OS store is not enough: many language runtimes ship
// their own trust store and ignore the system one. The guide therefore covers
// per-runtime configuration as well.
package wizard

import (
	"fmt"
	"runtime"
	"strings"
)

// InstallGuide returns human-readable instructions for trusting the Doppel CA
// and pointing a client at the proxy.
func InstallGuide(certPath, fingerprint, proxyAddr string) string {
	var b strings.Builder

	fmt.Fprintln(&b, "Doppel CA generated.")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "  Certificate : %s\n", certPath)
	fmt.Fprintf(&b, "  SHA-256     : %s\n", fingerprint)
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "Verify this fingerprint matches the certificate before trusting it.")
	fmt.Fprintln(&b, "The CA is unique to this machine. Never share its private key.")
	fmt.Fprintln(&b)

	fmt.Fprintln(&b, "1. Trust the CA in the OS store")
	fmt.Fprintln(&b, osTrustCommand(certPath))
	if note := osTrustNote(); note != "" {
		fmt.Fprintln(&b, note)
	}
	fmt.Fprintln(&b)

	fmt.Fprintln(&b, "2. Trust the CA in language runtimes (they ignore the OS store)")
	fmt.Fprintf(&b, "   Python (requests) : set REQUESTS_CA_BUNDLE=%s\n", certPath)
	fmt.Fprintf(&b, "   Node.js           : set NODE_EXTRA_CA_CERTS=%s\n", certPath)
	fmt.Fprintf(&b, "   Go / curl         : set SSL_CERT_FILE=%s\n", certPath)
	fmt.Fprintln(&b)

	fmt.Fprintln(&b, "3. Point a client at the proxy")
	fmt.Fprintf(&b, "   HTTP CONNECT : set HTTPS_PROXY=http://%s\n", proxyAddr)
	fmt.Fprintf(&b, "   SOCKS5       : set HTTPS_PROXY=socks5://%s\n", proxyAddr)
	fmt.Fprintln(&b, "   The same port serves both protocols.")
	fmt.Fprintln(&b)

	fmt.Fprintln(&b, "To undo, remove the CA from every store above and delete:")
	fmt.Fprintf(&b, "   %s\n", certPath)

	return b.String()
}

// osTrustNote returns a platform-specific caveat shown beneath the trust
// command, or an empty string when there is nothing to add.
func osTrustNote() string {
	if runtime.GOOS == "windows" {
		return "   Note: tools using Windows Schannel (curl, .NET) reject a private\n" +
			"   CA during revocation checks. Disable revocation for them,\n" +
			"   for example: curl --ssl-no-revoke. OpenSSL-based tools are fine."
	}
	return ""
}

// osTrustCommand returns the platform-specific command that adds the CA to
// the system trust store.
func osTrustCommand(certPath string) string {
	switch runtime.GOOS {
	case "windows":
		return fmt.Sprintf("   certutil -addstore -user Root \"%s\"", certPath)
	case "darwin":
		return fmt.Sprintf("   sudo security add-trusted-cert -d -r trustRoot \\\n"+
			"     -k /Library/Keychains/System.keychain \"%s\"", certPath)
	default:
		return fmt.Sprintf("   sudo cp \"%s\" /usr/local/share/ca-certificates/doppel.crt \\\n"+
			"     && sudo update-ca-certificates", certPath)
	}
}
