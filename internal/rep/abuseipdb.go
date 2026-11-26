package rep

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/PalMeany/traced-cli/internal/cache"
)

// AbuseIPDBURL is the check endpoint (overridable in tests).
var AbuseIPDBURL = "https://api.abuseipdb.com/api/v2/check"

// AbuseIPDB is the part of the check answer we use.
type AbuseIPDB struct {
	Score       int    `json:"abuseConfidenceScore"`
	Reports     int    `json:"totalReports"`
	Users       int    `json:"numDistinctUsers"`
	LastReport  string `json:"lastReportedAt"`
	Whitelisted *bool  `json:"isWhitelisted"`
	Tor         bool   `json:"isTor"`
	Usage       string `json:"usageType"`
	ISP         string `json:"isp"`
	Domain      string `json:"domain"`
	Country     string `json:"countryCode"`
}

// ParseAbuseIPDB decodes {"data":{...}}.
func ParseAbuseIPDB(b []byte) (*AbuseIPDB, error) {
	var d struct {
		Data   *AbuseIPDB `json:"data"`
		Errors []struct {
			Detail string `json:"detail"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	if d.Data == nil {
		if len(d.Errors) > 0 {
			return nil, fmt.Errorf("%s", d.Errors[0].Detail)
		}
		return nil, fmt.Errorf("empty answer")
	}
	return d.Data, nil
}

// AbuseSource turns the answer into a source line.
func AbuseSource(a *AbuseIPDB) Source {
	s := Source{Name: "abuseipdb", Title: feedTitles["abuseipdb"], Matches: a.Reports}
	wl := a.Whitelisted != nil && *a.Whitelisted
	extra := []string{}
	if a.Usage != "" {
		extra = append(extra, a.Usage)
	}
	if a.ISP != "" {
		extra = append(extra, a.ISP)
	}
	if a.LastReport != "" {
		extra = append(extra, "last report "+a.LastReport[:min(10, len(a.LastReport))])
	}
	s.Details = extra
	switch {
	case wl:
		s.Status, s.Summary = StClean, fmt.Sprintf("whitelisted by AbuseIPDB (%d reports)", a.Reports)
	case a.Score == 0 && a.Reports == 0:
		s.Status, s.Summary = StClean, "no reports in 90 days"
	case a.Score == 0:
		s.Status, s.Score, s.Summary = StInfo, 3, fmt.Sprintf("confidence 0%%, %d old/low-trust reports", a.Reports)
	default:
		s.Status, s.Score = StListed, a.Score
		s.Summary = fmt.Sprintf("confidence %d%%, %d reports from %d users (90 days)", a.Score, a.Reports, a.Users)
	}
	return s
}

func checkAbuseIPDB(ctx context.Context, a netip.Addr, key string) Source {
	s := Source{Name: "abuseipdb", Title: feedTitles["abuseipdb"]}
	var raw json.RawMessage
	if !cache.Get("abuseipdb", a.String(), &raw) {
		c, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		u := AbuseIPDBURL + "?maxAgeInDays=90&ipAddress=" + url.QueryEscape(a.String())
		req, _ := http.NewRequestWithContext(c, "GET", u, nil)
		req.Header.Set("Key", key)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "traced-cli/1.2")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			s.Status, s.Summary = StError, "request failed: "+strings.TrimPrefix(err.Error(), "Get ")
			if c.Err() != nil {
				s.Summary = "timeout"
			}
			return s
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		switch resp.StatusCode {
		case 200:
		case 401, 403:
			s.Status, s.Summary = StError, "API key rejected (HTTP "+fmt.Sprint(resp.StatusCode)+")"
			return s
		case 429:
			s.Status, s.Summary = StSkipped, "skipped: daily quota exhausted (HTTP 429)"
			return s
		default:
			s.Status, s.Summary = StError, "HTTP "+fmt.Sprint(resp.StatusCode)
			return s
		}
		raw = b
		cache.Put("abuseipdb", a.String(), raw, 6*time.Hour)
	}
	d, err := ParseAbuseIPDB(raw)
	if err != nil {
		s.Status, s.Summary = StError, err.Error()
		return s
	}
	return AbuseSource(d)
}
