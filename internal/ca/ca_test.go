package ca

import (
	"crypto/x509"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerateProducesValidCA(t *testing.T) {
	a, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !a.caCert.IsCA {
		t.Error("generated certificate is not marked as a CA")
	}
	if a.caCert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("CA certificate cannot sign certificates")
	}
}

func TestLeafChainsToCA(t *testing.T) {
	a, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	leaf, err := a.LeafFor("example.com")
	if err != nil {
		t.Fatalf("LeafFor: %v", err)
	}

	parsed, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(a.caCert)
	if _, err := parsed.Verify(x509.VerifyOptions{
		DNSName:     "example.com",
		Roots:       roots,
		CurrentTime: time.Now(),
	}); err != nil {
		t.Fatalf("leaf does not verify against CA: %v", err)
	}
}

func TestLeafForCachesByHost(t *testing.T) {
	a, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	first, err := a.LeafFor("example.com:443")
	if err != nil {
		t.Fatalf("LeafFor: %v", err)
	}
	second, err := a.LeafFor("EXAMPLE.COM")
	if err != nil {
		t.Fatalf("LeafFor: %v", err)
	}
	if first != second {
		t.Error("expected cached certificate to be reused across host variants")
	}
}

func TestLeafForIPAddress(t *testing.T) {
	a, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	leaf, err := a.LeafFor("203.0.113.7")
	if err != nil {
		t.Fatalf("LeafFor: %v", err)
	}
	parsed, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if len(parsed.IPAddresses) != 1 {
		t.Fatalf("expected 1 IP SAN, got %d", len(parsed.IPAddresses))
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	a, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca.key")
	if err := a.Save(certPath, keyPath); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load(certPath, keyPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Fingerprint() != a.Fingerprint() {
		t.Error("fingerprint changed across save/load")
	}

	leaf, err := loaded.LeafFor("example.org")
	if err != nil {
		t.Fatalf("LeafFor after load: %v", err)
	}
	parsed, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(a.caCert)
	if _, err := parsed.Verify(x509.VerifyOptions{DNSName: "example.org", Roots: roots}); err != nil {
		t.Fatalf("leaf from loaded CA does not verify: %v", err)
	}
}
