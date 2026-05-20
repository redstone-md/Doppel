package upstream

import (
	"testing"

	"golang.org/x/net/http2"

	"github.com/redstone-md/Doppel/internal/profile"
)

func TestH2SettingsPreserveProfileOrder(t *testing.T) {
	p := &profile.Profile{HTTP2: &profile.HTTP2Profile{Settings: []profile.HTTP2Setting{
		{Name: "INITIAL_WINDOW_SIZE", Value: 6291456},
		{Name: "HEADER_TABLE_SIZE", Value: 65536},
		{Name: "MAX_HEADER_LIST_SIZE", Value: 262144},
	}}}
	settings, err := h2Settings(p)
	if err != nil {
		t.Fatal(err)
	}
	want := []http2.SettingID{
		http2.SettingInitialWindowSize,
		http2.SettingHeaderTableSize,
		http2.SettingMaxHeaderListSize,
	}
	for i, id := range want {
		if settings[i].ID != id {
			t.Fatalf("setting %d = %v, want %v", i, settings[i].ID, id)
		}
	}
}

func TestH2ConnectionWindowUpdateUsesProfile(t *testing.T) {
	p := &profile.Profile{HTTP2: &profile.HTTP2Profile{ConnectionWindowUpdate: 15663105}}
	if got := h2ConnectionWindowUpdate(p); got != 15663105 {
		t.Fatalf("connection window update = %d", got)
	}
}
