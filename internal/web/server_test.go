package web

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/PalMeany/traced-cli/internal/store"
)

func TestGuardAndAPI(t *testing.T) {
	t.Setenv("TRACED_DATA_DIR", t.TempDir())
	s, err := Start(Options{Listen: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.st = store.Default()
	get := func(host, path, origin string) int {
		req, _ := http.NewRequest("GET", s.URL+path, nil)
		if host != "" {
			req.Host = host
		}
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if c := get("", "/api/traces", ""); c != 200 {
		t.Fatalf("list: %d", c)
	}
	if c := get("", "/", ""); c != 200 {
		t.Fatalf("index: %d", c)
	}
	if c := get("evil.example:80", "/api/traces", ""); c != 403 {
		t.Fatalf("rebinding host accepted: %d", c)
	}
	if c := get("", "/api/traces", "http://evil.example"); c != 403 {
		t.Fatalf("cross origin accepted: %d", c)
	}
	if c := get("", "/api/run?target=-oProxy", ""); c != 400 {
		t.Fatalf("bad target accepted: %d", c)
	}
	_ = httptest.NewRecorder
}
