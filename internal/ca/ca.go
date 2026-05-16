// Package ca implements a local certificate authority used by Doppel to
// terminate TLS for MITM interception.
//
// On first run Doppel generates a unique CA per machine. The CA private key
// never leaves the host and must be protected: anyone holding it can forge
// certificates for any domain the host trusts. The CA is generated locally
// and is never shared or embedded in distributed binaries.
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	caValidity   = 10 * 365 * 24 * time.Hour
	leafValidity = 365 * 24 * time.Hour
	clockSkew    = time.Hour
)

// Authority is a local certificate authority. It signs short-lived leaf
// certificates on demand so Doppel can present a trusted certificate for any
// host the client connects to. Leaf certificates are cached in memory keyed
// by host. Authority is safe for concurrent use.
type Authority struct {
	caCert  *x509.Certificate
	caKey   *ecdsa.PrivateKey
	caDER   []byte
	leafKey *ecdsa.PrivateKey

	mu    sync.RWMutex
	cache map[string]*tls.Certificate
}

// Generate creates a new self-signed CA together with a fresh key shared by
// all minted leaf certificates.
func Generate() (*Authority, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}

	serial, err := randSerial()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Doppel Local Root CA",
			Organization: []string{"Doppel"},
		},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("create CA certificate: %w", err)
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}

	return &Authority{
		caCert:  caCert,
		caKey:   caKey,
		caDER:   der,
		leafKey: leafKey,
		cache:   make(map[string]*tls.Certificate),
	}, nil
}

// Load reads a previously persisted CA from disk. The leaf key is regenerated
// on every load since leaf certificates are short-lived and held in memory
// only.
func Load(certPath, keyPath string) (*Authority, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read CA certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read CA key: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, errors.New("ca: invalid certificate PEM")
	}
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("ca: invalid private key PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA key: %w", err)
	}
	caKey, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("ca: private key is not ECDSA")
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}

	return &Authority{
		caCert:  caCert,
		caKey:   caKey,
		caDER:   certBlock.Bytes,
		leafKey: leafKey,
		cache:   make(map[string]*tls.Certificate),
	}, nil
}

// Save writes the CA certificate and private key to disk. The key file is
// created with 0600 permissions so only the owner can read it.
func (a *Authority) Save(certPath, keyPath string) error {
	keyDER, err := x509.MarshalPKCS8PrivateKey(a.caKey)
	if err != nil {
		return fmt.Errorf("marshal CA key: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.caDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		return fmt.Errorf("create certificate directory: %w", err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return fmt.Errorf("write CA certificate: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return fmt.Errorf("create key directory: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write CA key: %w", err)
	}
	return nil
}

// LeafFor returns a leaf certificate valid for host, minting and caching it on
// first request. host may include a port, which is stripped.
func (a *Authority) LeafFor(host string) (*tls.Certificate, error) {
	host = normalizeHost(host)

	a.mu.RLock()
	cached, ok := a.cache[host]
	a.mu.RUnlock()
	if ok {
		return cached, nil
	}

	cert, err := a.mint(host)
	if err != nil {
		return nil, err
	}

	a.mu.Lock()
	if existing, ok := a.cache[host]; ok {
		cert = existing
	} else {
		a.cache[host] = cert
	}
	a.mu.Unlock()
	return cert, nil
}

// ServerTLSConfig returns a tls.Config that terminates TLS for host. The
// supplied host is used as the default, but an SNI value from the client
// takes precedence so a single config also serves redirected hosts.
func (a *Authority) ServerTLSConfig(host string, nextProtos []string) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: nextProtos,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := host
			if hello.ServerName != "" {
				name = hello.ServerName
			}
			return a.LeafFor(name)
		},
	}
}

// CertificatePEM returns the PEM-encoded CA certificate. This is the file the
// user installs into their trust store.
func (a *Authority) CertificatePEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.caDER})
}

// Fingerprint returns the hex-encoded SHA-256 of the CA certificate, used to
// let the user verify the certificate they install matches this machine.
func (a *Authority) Fingerprint() string {
	sum := sha256.Sum256(a.caDER)
	return hex.EncodeToString(sum[:])
}

func (a *Authority) mint(host string) (*tls.Certificate, error) {
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-clockSkew),
		NotAfter:     now.Add(leafValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.caCert, &a.leafKey.PublicKey, a.caKey)
	if err != nil {
		return nil, fmt.Errorf("mint leaf for %q: %w", host, err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  a.leafKey,
	}, nil
}

func randSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %w", err)
	}
	return serial, nil
}

func normalizeHost(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(host)
}
