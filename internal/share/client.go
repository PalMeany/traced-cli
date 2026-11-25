package share

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/PalMeany/traced-cli/internal/app"
	"github.com/PalMeany/traced-cli/internal/trace"
)

// DefaultURL is the public map server.
const DefaultURL = "https://traced.netkitty.dev"

// Mirrors are tried in order when DefaultURL is unreachable (some ISPs cut
// TLS by SNI). The https mirror proxies to the same storage; the plain-http
// fallback only carries the upload, the link stays on DefaultURL.
var Mirrors = []string{"https://traced.nuvira.su", "http://traced.netkitty.dev"}

// UploadAny tries DefaultURL and then the mirrors, each with its own timeout.
// Links obtained through an https mirror point at that mirror.
func UploadAny(ctx context.Context, r *trace.Result, per time.Duration) (*Response, error) {
	var firstErr error
	for _, base := range append([]string{DefaultURL}, Mirrors...) {
		c, cancel := context.WithTimeout(ctx, per)
		resp, err := Upload(c, base, r)
		cancel()
		if err == nil {
			if strings.HasPrefix(base, "https://") && base != DefaultURL && strings.HasPrefix(resp.URL, DefaultURL) {
				resp.URL = base + strings.TrimPrefix(resp.URL, DefaultURL)
			}
			return resp, nil
		}
		if firstErr == nil {
			firstErr = err
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, firstErr
}

// Response of POST /api/traces.
type Response struct {
	ID      string    `json:"id"`
	URL     string    `json:"url"`
	Expires time.Time `json:"expires"`
}

// Upload publishes a sanitized copy of r on the server at base and returns
// the public map link. Only the trace goes out: no client identifiers are
// added beyond what the network already sees.
func Upload(ctx context.Context, base string, r *trace.Result) (*Response, error) {
	if base == "" {
		base = DefaultURL
	}
	u, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("bad share url %q", base)
	}
	clean, err := Sanitize(r)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(clean)
	if err != nil {
		return nil, err
	}
	if len(body) > MaxBody {
		return nil, fmt.Errorf("trace too large (%d KB)", len(body)>>10)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", u.String()+"/api/traces", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "traced/"+app.Version)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(rb))
		if len(msg) > 120 || strings.Contains(msg, "<") {
			msg = ""
		}
		return nil, fmt.Errorf("server said %s %s", resp.Status, msg)
	}
	var out Response
	if err := json.Unmarshal(rb, &out); err != nil || out.ID == "" {
		return nil, errors.New("unexpected server reply")
	}
	if out.URL == "" {
		out.URL = u.String() + "/t/" + out.ID
	}
	return &out, nil
}
