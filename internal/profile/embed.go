package profile

import (
	"embed"
	"fmt"
	"sort"
	"strings"
)

//go:embed builtin/*.json
var builtinFS embed.FS

// Builtin returns the profiles shipped with Doppel, keyed by profile name.
func Builtin() (map[string]*Profile, error) {
	entries, err := builtinFS.ReadDir("builtin")
	if err != nil {
		return nil, fmt.Errorf("read builtin profiles: %w", err)
	}

	out := make(map[string]*Profile)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := builtinFS.ReadFile("builtin/" + e.Name())
		if err != nil {
			return nil, fmt.Errorf("read builtin profile %s: %w", e.Name(), err)
		}
		p, err := parse(data)
		if err != nil {
			return nil, fmt.Errorf("builtin profile %s: %w", e.Name(), err)
		}
		out[p.Name] = p
	}
	return out, nil
}

// BuiltinNames returns the sorted names of the built-in profiles.
func BuiltinNames() ([]string, error) {
	profiles, err := Builtin()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(profiles))
	for name := range profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}
