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
	"net/http"
	"os"
	"os/signal"
	"sort"

	"github.com/Rxflex/doppel/internal/ca"
	"github.com/Rxflex/doppel/internal/config"
	"github.com/Rxflex/doppel/internal/mitm"
	"github.com/Rxflex/doppel/internal/profile"
	"github.com/Rxflex/doppel/internal/proxy"
	"github.com/Rxflex/doppel/internal/upstream"
	"github.com/Rxflex/doppel/internal/wizard"
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

	server := &proxy.Server{
		Addr:   cfg.Addr,
		Logger: logger,
		Interceptor: &mitm.Interceptor{
			CA:      authority,
			Profile: selected,
			Dialer:  &upstream.Dialer{SkipVerify: *insecure},
			Logger:  logger,
		},
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	logger.Info("starting doppel", "version", version, "profile", selected.Name)
	return server.ListenAndServe(ctx)
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
  profiles   List available identity profiles
  ca         Show or export the local CA certificate
  verify     Check the emulated TLS fingerprint against a remote service
  version    Print the version

Run "doppel <command> -h" for command-specific flags.
`)
}
