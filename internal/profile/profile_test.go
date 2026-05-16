package profile

import (
	"net/http"
	"testing"
)

func TestBuiltinProfilesLoad(t *testing.T) {
	profiles, err := Builtin()
	if err != nil {
		t.Fatalf("Builtin: %v", err)
	}
	if len(profiles) == 0 {
		t.Fatal("expected at least one built-in profile")
	}
	for name, p := range profiles {
		if err := p.Validate(); err != nil {
			t.Errorf("built-in profile %q is invalid: %v", name, err)
		}
	}
	if _, ok := profiles["iphone15-safari"]; !ok {
		t.Error("expected built-in profile iphone15-safari")
	}
}

func TestValidateRejectsIncomplete(t *testing.T) {
	cases := map[string]Profile{
		"missing name":         {ClientHello: "chrome", UserAgent: "ua", ALPN: []string{"h2"}},
		"missing client hello": {Name: "x", UserAgent: "ua", ALPN: []string{"h2"}},
		"missing user agent":   {Name: "x", ClientHello: "chrome", ALPN: []string{"h2"}},
		"missing alpn":         {Name: "x", ClientHello: "chrome", UserAgent: "ua"},
	}
	for name, p := range cases {
		if err := p.Validate(); err == nil {
			t.Errorf("%s: expected validation error, got nil", name)
		}
	}
}

func TestApplySetsHeaders(t *testing.T) {
	p := &Profile{
		Name:      "x",
		UserAgent: "doppel-test-agent",
		Headers: HeaderProfile{
			Set: map[string]string{"Accept-Language": "en-US,en;q=0.9"},
		},
	}
	req, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
	req.Header.Set("User-Agent", "leaky-scraper/1.0")
	p.Apply(req)

	if got := req.Header.Get("User-Agent"); got != "doppel-test-agent" {
		t.Errorf("User-Agent = %q, want profile value", got)
	}
	if got := req.Header.Get("Accept-Language"); got != "en-US,en;q=0.9" {
		t.Errorf("Accept-Language = %q, want injected value", got)
	}
}

func TestOrderHeaders(t *testing.T) {
	p := &Profile{
		Headers: HeaderProfile{Order: []string{"host", "user-agent", "accept"}},
	}
	h := http.Header{
		"Accept":       {"*/*"},
		"User-Agent":   {"ua"},
		"X-Extra":      {"1"},
		"Authorization": {"token"},
	}
	got := p.OrderHeaders(h)

	// Ordered keys come first in profile order; "host" is absent from h.
	if got[0] != "User-Agent" || got[1] != "Accept" {
		t.Fatalf("profile-ordered keys wrong: %v", got)
	}
	// Remaining keys follow alphabetically.
	if got[2] != "Authorization" || got[3] != "X-Extra" {
		t.Fatalf("trailing keys not alphabetical: %v", got)
	}
}
