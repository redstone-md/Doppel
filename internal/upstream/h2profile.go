package upstream

import (
	"fmt"
	"strings"

	"golang.org/x/net/http2"

	"github.com/redstone-md/Doppel/internal/profile"
)

func h2Settings(p *profile.Profile) ([]http2.Setting, error) {
	if p.HTTP2 == nil || len(p.HTTP2.Settings) == 0 {
		return defaultH2Settings(), nil
	}
	out := make([]http2.Setting, 0, len(p.HTTP2.Settings))
	for _, setting := range p.HTTP2.Settings {
		id, err := h2SettingID(setting.Name)
		if err != nil {
			return nil, err
		}
		out = append(out, http2.Setting{ID: id, Val: setting.Value})
	}
	return out, nil
}

func defaultH2Settings() []http2.Setting {
	return []http2.Setting{
		{ID: http2.SettingEnablePush, Val: 0},
		{ID: http2.SettingInitialWindowSize, Val: 4194304},
		{ID: http2.SettingMaxFrameSize, Val: 16384},
		{ID: http2.SettingMaxHeaderListSize, Val: 10485760},
	}
}

func h2SettingID(name string) (http2.SettingID, error) {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "HEADER_TABLE_SIZE":
		return http2.SettingHeaderTableSize, nil
	case "ENABLE_PUSH":
		return http2.SettingEnablePush, nil
	case "MAX_CONCURRENT_STREAMS":
		return http2.SettingMaxConcurrentStreams, nil
	case "INITIAL_WINDOW_SIZE":
		return http2.SettingInitialWindowSize, nil
	case "MAX_FRAME_SIZE":
		return http2.SettingMaxFrameSize, nil
	case "MAX_HEADER_LIST_SIZE":
		return http2.SettingMaxHeaderListSize, nil
	default:
		return 0, fmt.Errorf("unknown HTTP/2 setting %q", name)
	}
}

func h2ConnectionWindowUpdate(p *profile.Profile) uint32 {
	if p.HTTP2 != nil && p.HTTP2.ConnectionWindowUpdate > 0 {
		return p.HTTP2.ConnectionWindowUpdate
	}
	return 1073741824
}

func h2PseudoHeaderOrder(p *profile.Profile) []string {
	if p.HTTP2 != nil && len(p.HTTP2.PseudoHeaderOrder) > 0 {
		return p.HTTP2.PseudoHeaderOrder
	}
	return []string{":method", ":authority", ":scheme", ":path"}
}
