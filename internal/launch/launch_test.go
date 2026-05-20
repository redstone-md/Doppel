package launch

import (
	"context"
	"slices"
	"testing"
)

func TestProxyEnvSetsHTTPSAndCAWithoutLeakingOtherProxies(t *testing.T) {
	opts := Options{ProxyAddr: "127.0.0.1:8080", CACertPath: "/tmp/doppel-ca.pem"}
	env := ProxyEnv([]string{
		"PATH=/bin",
		"HTTPS_PROXY=old",
		"HTTP_PROXY=http://upstream",
		"ALL_PROXY=socks5://upstream",
	}, opts)

	want := map[string]string{
		"HTTPS_PROXY=http://127.0.0.1:8080":      "missing HTTPS_PROXY",
		"https_proxy=http://127.0.0.1:8080":      "missing lowercase https_proxy",
		"NO_PROXY=localhost,127.0.0.1,::1":       "missing NO_PROXY",
		"REQUESTS_CA_BUNDLE=/tmp/doppel-ca.pem":  "missing requests CA bundle",
		"NODE_EXTRA_CA_CERTS=/tmp/doppel-ca.pem": "missing Node CA bundle",
		"SSL_CERT_FILE=/tmp/doppel-ca.pem":       "missing SSL_CERT_FILE",
	}
	for entry, message := range want {
		if !slices.Contains(env, entry) {
			t.Fatal(message)
		}
	}
	for _, leaked := range []string{
		"HTTPS_PROXY=old",
		"HTTP_PROXY=http://upstream",
		"ALL_PROXY=socks5://upstream",
	} {
		if slices.Contains(env, leaked) {
			t.Fatalf("unexpected inherited proxy: %s", leaked)
		}
	}
}

func TestAppendChromiumArgsDefaultsToHTTPSOnly(t *testing.T) {
	args := AppendChromiumArgs([]string{"--user-data-dir=/tmp/app"}, Options{
		ProxyAddr: "127.0.0.1:8080",
	})

	want := []string{
		"--user-data-dir=/tmp/app",
		"--proxy-server=https=http://127.0.0.1:8080",
		"--proxy-bypass-list=<local>",
	}
	if !slices.Equal(args, want) {
		t.Fatalf("args mismatch\nwant: %#v\n got: %#v", want, args)
	}
}

func TestCommandAppendsChromiumArgsWhenEnabled(t *testing.T) {
	cmd, err := Command(context.Background(), Options{
		ProxyAddr:       "127.0.0.1:8080",
		CACertPath:      "/tmp/doppel-ca.pem",
		IncludeEnv:      true,
		IncludeChromium: true,
		BypassList:      "localhost;127.0.0.1",
	}, []string{"electron-app", "--existing"})
	if err != nil {
		t.Fatal(err)
	}

	wantArgs := []string{
		"--existing",
		"--proxy-server=https=http://127.0.0.1:8080",
		"--proxy-bypass-list=localhost;127.0.0.1",
	}
	if !slices.Equal(cmd.Args, append([]string{"electron-app"}, wantArgs...)) {
		t.Fatalf("command args mismatch: %#v", cmd.Args)
	}
	if len(cmd.Env) == 0 {
		t.Fatal("expected proxy environment")
	}
}
