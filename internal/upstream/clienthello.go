// Package upstream establishes connections to real servers using a TLS
// ClientHello that emulates a chosen device, then carries HTTP/1.1 or HTTP/2
// over them.
//
// This is where the JA3/JA4 fingerprint is produced: the ClientHello sent to
// the server is built from a uTLS template, not from Go's standard TLS stack.
package upstream

import (
	"fmt"
	"sort"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// clientHelloIDs maps the identifiers used in profiles to uTLS ClientHello
// templates. The "_Auto" templates track the latest version uTLS supports for
// each browser, which keeps profiles working as uTLS is updated.
var clientHelloIDs = map[string]utls.ClientHelloID{
	"chrome":     utls.HelloChrome_Auto,
	"firefox":    utls.HelloFirefox_Auto,
	"safari":     utls.HelloSafari_Auto,
	"safari-ios": utls.HelloIOS_Auto,
	"ios":        utls.HelloIOS_Auto,
	"edge":       utls.HelloEdge_Auto,
	"randomized": utls.HelloRandomizedALPN,
}

// resolveClientHello returns the uTLS template for a profile's client_hello.
func resolveClientHello(name string) (utls.ClientHelloID, error) {
	id, ok := clientHelloIDs[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return utls.ClientHelloID{}, fmt.Errorf("upstream: unknown client_hello %q (supported: %s)",
			name, strings.Join(ClientHelloNames(), ", "))
	}
	return id, nil
}

// ClientHelloNames returns the sorted list of supported client_hello values.
func ClientHelloNames() []string {
	names := make([]string, 0, len(clientHelloIDs))
	for name := range clientHelloIDs {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
