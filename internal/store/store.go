// Package store keeps finished traces as JSON files in ~/.local/share/traced
// and computes diffs between two traces.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/PalMeany/traced-cli/internal/trace"
)

// Store is a directory of trace files.
type Store struct{ Dir string }

// Default returns the store in $XDG_DATA_HOME/traced (~/.local/share/traced).
func Default() *Store {
	if d := os.Getenv("TRACED_DATA_DIR"); d != "" {
		return &Store{Dir: d}
	}
	base := os.Getenv("XDG_DATA_HOME")
	if base == "" {
		h, _ := os.UserHomeDir()
		base = filepath.Join(h, ".local", "share")
	}
	return &Store{Dir: filepath.Join(base, "traced")}
}

func (s *Store) tracesDir() string { return filepath.Join(s.Dir, "traces") }

// NewID makes a sortable unique id.
func NewID(t time.Time) string {
	const al = "abcdefghjkmnpqrstuvwxyz23456789"
	b := []byte{al[rand.Intn(len(al))], al[rand.Intn(len(al))], al[rand.Intn(len(al))]}
	return t.Format("060102-150405") + "-" + string(b)
}

// Save writes a trace (assigning an id when missing).
func (s *Store) Save(r *trace.Result) error {
	if r.ID == "" {
		r.ID = NewID(r.Started)
	}
	if err := os.MkdirAll(s.tracesDir(), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(r, "", " ")
	if err != nil {
		return err
	}
	p := filepath.Join(s.tracesDir(), r.ID+".json")
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Summary is a short listing entry.
type Summary struct {
	ID       string         `json:"id"`
	Target   string         `json:"target"`
	TargetIP string         `json:"target_ip"`
	Protocol trace.Protocol `json:"protocol"`
	Port     int            `json:"port,omitempty"`
	Started  time.Time      `json:"started"`
	Hops     int            `json:"hops"`
	Reached  bool           `json:"reached"`
	RTT      float64        `json:"rtt_ms"`
}

// IDs returns trace ids, newest first.
func (s *Store) IDs() []string {
	m, _ := filepath.Glob(filepath.Join(s.tracesDir(), "*.json"))
	var ids []string
	for _, f := range m {
		ids = append(ids, strings.TrimSuffix(filepath.Base(f), ".json"))
	}
	sort.Sort(sort.Reverse(sort.StringSlice(ids)))
	return ids
}

// List returns up to n summaries, newest first (n<=0: all).
func (s *Store) List(n int) []Summary {
	var out []Summary
	for _, id := range s.IDs() {
		if n > 0 && len(out) >= n {
			break
		}
		r, err := s.load(id)
		if err != nil {
			continue
		}
		out = append(out, Summarize(r))
	}
	return out
}

// Summarize builds a listing entry.
func Summarize(r *trace.Result) Summary {
	sm := Summary{ID: r.ID, Target: r.Target, TargetIP: r.TargetIP, Protocol: r.Protocol, Port: r.Port,
		Started: r.Started, Hops: len(r.Hops), Reached: r.Reached}
	if len(r.Hops) > 0 {
		sm.RTT = r.Hops[len(r.Hops)-1].AvgRTT()
	}
	return sm
}

func (s *Store) load(id string) (*trace.Result, error) {
	b, err := os.ReadFile(filepath.Join(s.tracesDir(), id+".json"))
	if err != nil {
		return nil, err
	}
	var r trace.Result
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	if r.ID == "" {
		r.ID = id
	}
	return &r, nil
}

// Resolve maps a reference ("1" = newest, "2" = previous, full id, unique prefix, "last") to an id.
func (s *Store) Resolve(ref string) (string, error) {
	ids := s.IDs()
	if len(ids) == 0 {
		return "", errors.New("history is empty")
	}
	if ref == "last" || ref == "latest" {
		return ids[0], nil
	}
	if n, err := strconv.Atoi(ref); err == nil && n >= 1 && n <= 9999 && len(ref) < 5 {
		if n > len(ids) {
			return "", fmt.Errorf("only %d traces in history", len(ids))
		}
		return ids[n-1], nil
	}
	var match []string
	for _, id := range ids {
		if id == ref {
			return id, nil
		}
		if strings.HasPrefix(id, ref) || strings.HasSuffix(id, ref) {
			match = append(match, id)
		}
	}
	switch len(match) {
	case 0:
		return "", fmt.Errorf("no trace %q", ref)
	case 1:
		return match[0], nil
	}
	return "", fmt.Errorf("ambiguous trace reference %q (%d matches)", ref, len(match))
}

// Load reads a trace by reference.
func (s *Store) Load(ref string) (*trace.Result, error) {
	id, err := s.Resolve(ref)
	if err != nil {
		return nil, err
	}
	return s.load(id)
}
