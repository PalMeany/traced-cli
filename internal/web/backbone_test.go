package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PalMeany/traced-cli/internal/backbone"
)

const testSVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 400">
<path d="M10 10 L790 10" stroke="#aaaaaa"/>
<path d="M100 100 L400 120 L700 300" stroke="#e30613" fill="none"/>
<path d="M400 120 L420 380" stroke="#e30613" fill="none"/>
<circle cx="100" cy="100" r="3" fill="#e30613"/><circle cx="400" cy="120" r="3" fill="#e30613"/>
<circle cx="700" cy="300" r="3" fill="#e30613"/><circle cx="420" cy="380" r="3" fill="#e30613"/></svg>`

func multipartBody(t *testing.T, fields map[string]string, file []byte) (*bytes.Buffer, string) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		mw.WriteField(k, v)
	}
	if file != nil {
		fw, _ := mw.CreateFormFile("file", "map.svg")
		fw.Write(file)
	}
	mw.Close()
	return &buf, mw.FormDataContentType()
}

func TestBackboneParseAPI(t *testing.T) {
	t.Setenv("TRACED_CACHE_DIR", t.TempDir())
	t.Setenv("TRACED_VISION_API_KEY", "")
	t.Setenv("GEMINI_API_KEY", "")
	t.Setenv("GOOGLE_API_KEY", "")
	allowed := 2
	h := BackboneParse(ParseLimits{MaxBytes: 2048, AllowSave: true, Offline: true, Allow: func(*http.Request) bool { allowed--; return allowed >= 0 }})
	post := func(fields map[string]string, file []byte) (int, map[string]any) {
		body, ct := multipartBody(t, fields, file)
		req := httptest.NewRequest("POST", "/api/backbone/parse", body)
		req.Header.Set("Content-Type", ct)
		rec := httptest.NewRecorder()
		h(rec, req)
		var out map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	code, out := post(map[string]string{"provider": "Test Net", "asn": "AS64500", "region": "europe", "save": "1"}, []byte(testSVG))
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	layer := out["layer"].(map[string]any)
	meta := layer["traced"].(map[string]any)
	if meta["slug"] != "test-net-as64500" || meta["links"].(float64) != 3 || meta["nodes"].(float64) != 4 || out["saved"] != true {
		t.Fatalf("%v", meta)
	}
	if _, err := os.Stat(filepath.Join(backbone.Dir(), "test-net-as64500.geojson")); err != nil {
		t.Fatal("not saved:", err)
	}
	// the layer endpoint now includes it
	rec := httptest.NewRecorder()
	BackboneLayer(true, 0)(rec, httptest.NewRequest("GET", "/api/backbones", nil))
	if !strings.Contains(rec.Body.String(), "test-net-as64500") {
		t.Fatalf("layer endpoint: %.300s", rec.Body.String())
	}
	if code, out = post(map[string]string{"provider": "Big"}, bytes.Repeat([]byte("x"), 4096)); code != 413 {
		t.Fatalf("size limit: %d %v", code, out)
	}
	if code, _ = post(map[string]string{"provider": "X"}, []byte(testSVG)); code != 429 {
		t.Fatalf("rate limit: %d", code)
	}
}

func TestBackboneParseErrors(t *testing.T) {
	t.Setenv("TRACED_VISION_API_KEY", "")
	t.Setenv("GEMINI_API_KEY", "")
	t.Setenv("GOOGLE_API_KEY", "")
	h := BackboneParse(ParseLimits{MaxBytes: 1 << 20, Offline: true})
	for i, tc := range []struct {
		fields map[string]string
		file   []byte
		code   int
		msg    string
	}{
		{map[string]string{"provider": "X"}, nil, 400, "file"},
		{map[string]string{}, []byte(testSVG), 400, "provider"},
		{map[string]string{"provider": "X", "engine": "llm"}, []byte(testSVG), 400, "disabled"},
		{map[string]string{"provider": "X"}, []byte(testSVG), 422, "reference"},
		{map[string]string{"provider": "X", "region": "europe", "save": "1"}, []byte(testSVG), 200, "not stored"},
	} {
		body, ct := multipartBody(t, tc.fields, tc.file)
		req := httptest.NewRequest("POST", "/api/backbone/parse", body)
		req.Header.Set("Content-Type", ct)
		rec := httptest.NewRecorder()
		h(rec, req)
		if rec.Code != tc.code || !strings.Contains(rec.Body.String(), tc.msg) {
			t.Errorf("case %d: %d %s", i, rec.Code, rec.Body.String())
		}
	}
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest("GET", "/api/backbone/parse", nil))
	if rec.Code != 405 {
		t.Fatal(rec.Code)
	}
	_ = fmt.Sprint()
}
