// Command doppel is a transparent TLS identity proxy. It accepts SOCKS5 or
// HTTP CONNECT clients, terminates their TLS, and re-originates each request
// upstream with the TLS fingerprint and headers of a chosen device profile.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"time"

	"github.com/redstone-md/Doppel/internal/ca"
	"github.com/redstone-md/Doppel/internal/config"
	"github.com/redstone-md/Doppel/internal/launch"
	"github.com/redstone-md/Doppel/internal/mitm"
	"github.com/redstone-md/Doppel/internal/profile"
	"github.com/redstone-md/Doppel/internal/proxy"
	"github.com/redstone-md/Doppel/internal/upstream"
	"github.com/redstone-md/Doppel/internal/wizard"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "0.1.0-dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch cmd := os.Args[1]; cmd {
	case "init":
		err = cmdInit(os.Args[2:])
	case "run":
		err = cmdRun(os.Args[2:])
	case "launch":
		err = cmdLaunch(os.Args[2:])
	case "profiles":
		err = cmdProfiles(os.Args[2:])
	case "ca":
		err = cmdCA(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Println("doppel", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "doppel: unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "doppel: "+err.Error())
		os.Exit(1)
	}
}

// cmdInit generates the local CA and prints the setup guide.
func cmdInit(args []string) error {
	cfg, err := config.Default()
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dataDir := fs.String("data", cfg.DataDir, "data directory")
	addr := fs.String("addr", cfg.Addr, "proxy address shown in the setup guide")
	force := fs.Bool("force", false, "regenerate the CA even if one already exists")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg.DataDir = *dataDir

	var authority *ca.Authority
	switch {
	case cfg.CAExists() && !*force:
		if authority, err = ca.Load(cfg.CACertPath(), cfg.CAKeyPath()); err != nil {
			return err
		}
		fmt.Println("Existing CA found; reusing it. Pass -force to regenerate.")
		fmt.Println()
	default:
		if authority, err = ca.Generate(); err != nil {
			return err
		}
		if err := authority.Save(cfg.CACertPath(), cfg.CAKeyPath()); err != nil {
			return err
		}
	}

	fmt.Println(wizard.InstallGuide(cfg.CACertPath(), authority.Fingerprint(), *addr))
	return nil
}

// cmdRun starts the proxy.
func cmdRun(args []string) error {
	cfg, err := config.Default()
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	addr := fs.String("addr", cfg.Addr, "proxy listen address")
	profileName := fs.String("profile", cfg.Profile, "identity profile to emulate")
	dataDir := fs.String("data", cfg.DataDir, "data directory")
	verbose := fs.Bool("v", false, "verbose (debug) logging")
	insecure := fs.Bool("insecure", false, "skip upstream certificate verification (debugging only)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg.DataDir, cfg.Addr, cfg.Profile = *dataDir, *addr, *profileName

	logger := newLogger(*verbose)

	if !cfg.CAExists() {
		return fmt.Errorf("no CA found in %s; run 'doppel init' first", cfg.DataDir)
	}
	authority, err := ca.Load(cfg.CACertPath(), cfg.CAKeyPath())
	if err != nil {
		return err
	}

	selected, err := loadProfile(cfg, cfg.Profile)
	if err != nil {
		return err
	}

	transport := &upstream.RoundTripper{
		Dialer:  &upstream.Dialer{SkipVerify: *insecure},
		Profile: selected,
	}
	defer transport.Close()

	server := &proxy.Server{
		Addr:   cfg.Addr,
		Logger: logger,
		Interceptor: &mitm.Interceptor{
			CA:        authority,
			Profile:   selected,
			Transport: transport,
			Logger:    logger,
		},
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	logger.Info("starting doppel", "version", version, "profile", selected.Name)
	return server.ListenAndServe(ctx)
}

// cmdLaunch starts the proxy, launches a child application configured to use it,
// and stops the proxy when the child exits.
func cmdLaunch(args []string) error {
	cfg, err := config.Default()
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("launch", flag.ExitOnError)
	addr := fs.String("addr", cfg.Addr, "proxy listen address")
	profileName := fs.String("profile", cfg.Profile, "identity profile to emulate")
	dataDir := fs.String("data", cfg.DataDir, "data directory")
	verbose := fs.Bool("v", false, "verbose (debug) logging")
	insecure := fs.Bool("insecure", false, "skip upstream certificate verification (debugging only)")
	includeEnv := fs.Bool("env", true, "set HTTPS proxy and CA environment variables for the child")
	electron := fs.Bool("electron", false, "append Chromium/Electron proxy command-line switches")
	allSchemes := fs.Bool("all-schemes", false, "with -electron, proxy every Chromium URL scheme instead of HTTPS only")
	bypass := fs.String("bypass", "<local>", "Chromium proxy bypass list used with -electron")
	if err := fs.Parse(args); err != nil {
		return err
	}
	argv := fs.Args()
	if len(argv) == 0 {
		return fmt.Errorf("usage: doppel launch [flags] -- <command> [args...]")
	}
	cfg.DataDir, cfg.Addr, cfg.Profile = *dataDir, *addr, *profileName

	logger := newLogger(*verbose)

	if !cfg.CAExists() {
		return fmt.Errorf("no CA found in %s; run 'doppel init' first", cfg.DataDir)
	}
	authority, err := ca.Load(cfg.CACertPath(), cfg.CAKeyPath())
	if err != nil {
		return err
	}

	selected, err := loadProfile(cfg, cfg.Profile)
	if err != nil {
		return err
	}

	transport := &upstream.RoundTripper{
		Dialer:  &upstream.Dialer{SkipVerify: *insecure},
		Profile: selected,
	}
	defer transport.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.Addr, err)
	}

	server := &proxy.Server{
		Addr:   cfg.Addr,
		Logger: logger,
		Interceptor: &mitm.Interceptor{
			CA:        authority,
			Profile:   selected,
			Transport: transport,
			Logger:    logger,
		},
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(ctx, ln) }()

	proxyAddr := ln.Addr().String()
	cmd, err := launch.Command(ctx, launch.Options{
		ProxyAddr:       proxyAddr,
		CACertPath:      cfg.CACertPath(),
		IncludeEnv:      *includeEnv,
		IncludeChromium: *electron,
		ProxyAllSchemes: *allSchemes,
		BypassList:      *bypass,
	}, argv)
	if err != nil {
		stop()
		return err
	}

	logger.Info("launching app", "profile", selected.Name, "proxy", proxyAddr, "command", argv[0])
	runErr := cmd.Run()
	stop()

	select {
	case err := <-serveErr:
		if runErr == nil && err != nil {
			return err
		}
	case <-time.After(5 * time.Second):
		logger.Warn("proxy shutdown timed out; exiting with child status")
	}
	return runErr
}

// cmdProfiles lists every available identity profile.
func cmdProfiles(args []string) error {
	cfg, err := config.Default()
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("profiles", flag.ExitOnError)
	dataDir := fs.String("data", cfg.DataDir, "data directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg.DataDir = *dataDir

	profiles, source, err := allProfiles(cfg)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(profiles))
	for name := range profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Printf("%-22s [%-7s] %s\n", name, source[name], profiles[name].Description)
	}
	return nil
}

// cmdCA shows the local CA certificate and optionally exports it.
func cmdCA(args []string) error {
	cfg, err := config.Default()
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("ca", flag.ExitOnError)
	dataDir := fs.String("data", cfg.DataDir, "data directory")
	export := fs.String("export", "", "write the CA certificate to this path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg.DataDir = *dataDir

	if !cfg.CAExists() {
		return fmt.Errorf("no CA found in %s; run 'doppel init' first", cfg.DataDir)
	}
	authority, err := ca.Load(cfg.CACertPath(), cfg.CAKeyPath())
	if err != nil {
		return err
	}

	fmt.Printf("certificate : %s\n", cfg.CACertPath())
	fmt.Printf("private key : %s\n", cfg.CAKeyPath())
	fmt.Printf("SHA-256     : %s\n", authority.Fingerprint())

	if *export != "" {
		if err := os.WriteFile(*export, authority.CertificatePEM(), 0o644); err != nil {
			return fmt.Errorf("export CA certificate: %w", err)
		}
		fmt.Printf("exported    : %s\n", *export)
	}
	return nil
}

// cmdVerify fetches a fingerprint-reporting service through a profile and
// prints what the server observed. It exercises the uTLS path directly,
// without the proxy or CA.
func cmdVerify(args []string) error {
	cfg, err := config.Default()
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	profileName := fs.String("profile", cfg.Profile, "identity profile to test")
	url := fs.String("url", "https://get.ja3.zone/", "fingerprint-reporting endpoint")
	dataDir := fs.String("data", cfg.DataDir, "data directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg.DataDir = *dataDir

	selected, err := loadProfile(cfg, *profileName)
	if err != nil {
		return err
	}

	rt := &upstream.RoundTripper{Dialer: &upstream.Dialer{}, Profile: selected}
	defer rt.Close()

	req, err := http.NewRequest(http.MethodGet, *url, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	selected.Apply(req)

	resp, err := rt.RoundTrip(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	fmt.Printf("profile : %s\n", selected.Name)
	fmt.Printf("url     : %s\n", *url)
	fmt.Printf("status  : %s\n", resp.Status)
	fmt.Printf("protocol: %s\n", resp.Proto)
	fmt.Println("---")
	fmt.Println(string(body))
	return nil
}

// allProfiles returns the merged set of built-in and user profiles together
// with a map recording the origin of each.
func allProfiles(cfg config.Config) (map[string]*profile.Profile, map[string]string, error) {
	profiles, err := profile.Builtin()
	if err != nil {
		return nil, nil, err
	}
	source := make(map[string]string, len(profiles))
	for name := range profiles {
		source[name] = "builtin"
	}

	if _, err := os.Stat(cfg.ProfilesDir()); err == nil {
		userProfiles, err := profile.LoadDir(cfg.ProfilesDir())
		if err != nil {
			return nil, nil, err
		}
		for name, p := range userProfiles {
			profiles[name] = p
			source[name] = "user"
		}
	}
	return profiles, source, nil
}

func loadProfile(cfg config.Config, name string) (*profile.Profile, error) {
	profiles, _, err := allProfiles(cfg)
	if err != nil {
		return nil, err
	}
	p, ok := profiles[name]
	if !ok {
		return nil, fmt.Errorf("unknown profile %q (run 'doppel profiles' to list them)", name)
	}
	return p, nil
}

func newLogger(verbose bool) *slog.Logger {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

func usage() {
	fmt.Fprint(os.Stderr, `doppel - transparent TLS identity proxy

Usage:
  doppel <command> [flags]

Commands:
  init       Generate the local CA and print setup instructions
  run        Start the proxy
  launch     Start the proxy and run an application through it
  profiles   List available identity profiles
  ca         Show or export the local CA certificate
  verify     Check the emulated TLS fingerprint against a remote service
  version    Print the version

Run "doppel <command> -h" for command-specific flags.
`)
}
