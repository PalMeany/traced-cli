// Package cache is a tiny JSON disk cache in ~/.cache/traced (XDG_CACHE_HOME).
package cache

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	mu       sync.Mutex
	disabled bool
	dirOver  string
)

// Disable turns the cache off (for tests or --no-cache).
func Disable() { disabled = true }

// SetDir overrides the cache directory.
func SetDir(d string) { dirOver = d }

// Dir returns the cache root (~/.cache/traced).
func Dir() string {
	if dirOver != "" {
		return dirOver
	}
	if x := os.Getenv("TRACED_CACHE_DIR"); x != "" {
		return x
	}
	base := os.Getenv("XDG_CACHE_HOME")
	if base == "" {
		h, _ := os.UserHomeDir()
		base = filepath.Join(h, ".cache")
	}
	return filepath.Join(base, "traced")
}

type entry struct {
	Exp time.Time       `json:"exp"`
	V   json.RawMessage `json:"v"`
}

func path(ns, key string) string {
	h := sha1.Sum([]byte(key))
	return filepath.Join(Dir(), ns, hex.EncodeToString(h[:])[:24]+".json")
}

// Get loads a cached value into v. Returns false when missing or expired.
func Get(ns, key string, v any) bool {
	if disabled {
		return false
	}
	b, err := os.ReadFile(path(ns, key))
	if err != nil {
		return false
	}
	var e entry
	if json.Unmarshal(b, &e) != nil || time.Now().After(e.Exp) {
		return false
	}
	return json.Unmarshal(e.V, v) == nil
}

// Put stores v for ttl.
func Put(ns, key string, v any, ttl time.Duration) {
	if disabled {
		return
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return
	}
	b, _ := json.Marshal(entry{Exp: time.Now().Add(ttl), V: raw})
	p := path(ns, key)
	mu.Lock()
	defer mu.Unlock()
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	tmp := p + ".tmp"
	if os.WriteFile(tmp, b, 0o644) == nil {
		_ = os.Rename(tmp, p)
	}
}

// File returns a path inside the cache dir for raw files (geofeeds, PeeringDB dump).
func File(parts ...string) string {
	p := filepath.Join(append([]string{Dir()}, parts...)...)
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	return p
}

// Fresh reports whether file p exists and is younger than ttl.
func Fresh(p string, ttl time.Duration) bool {
	st, err := os.Stat(p)
	return err == nil && time.Since(st.ModTime()) < ttl
}
