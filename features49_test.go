package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func Test49LocalCountryFlagValidAndIndependentOfExtraRequest(t *testing.T) {
	a := automaticApp(t)
	a.geo.Exit = GeoInfo{Code: "FR", Country: "France"}
	g := a.exitLocation()
	b, e := base64.StdEncoding.DecodeString(strings.TrimPrefix(g.FlagImage, "data:image/svg+xml;base64,"))
	if e != nil || !bytes.Contains(b, []byte(`id="flag-icons-fr"`)) {
		t.Fatal("France flag missing", e)
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, httptest.NewRequest("GET", "/flags/fr.svg", nil))
	if w.Code != 200 {
		t.Fatal("flag asset not served", w.Code)
	}
	if !strings.HasPrefix(localFlagImage("../../etc/passwd"), "data:image/svg+xml;base64,") {
		t.Fatal("unknown flag lacks fallback")
	}
}
func Test49ImageSearchProxySanitizesAndRestrictsSources(t *testing.T) {
	a := automaticApp(t)
	var pngImage bytes.Buffer
	png.Encode(&pngImage, image.NewRGBA(image.Rect(0, 0, 2, 2)))
	a.imageHTTP = &http.Client{Transport: feature45Transport(func(r *http.Request) (*http.Response, error) {
		body := `{"query":{"pages":[{"title":"File:Landscape.jpg","imageinfo":[{"thumburl":"https://thumb.wikimedia.org/a.jpg","descriptionurl":"https://commons.wikimedia.org/wiki/File:Landscape.jpg","extmetadata":{"Artist":{"value":"<b>Artist</b>"},"LicenseShortName":{"value":"CC BY"}}}]},{"title":"File:Bad","imageinfo":[{"thumburl":"http://127.0.0.1/private","descriptionurl":"https://commons.wikimedia.org/wiki/File:Bad"}]}]}}`
		if r.URL.Host == "thumb.wikimedia.org" {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(pngImage.Bytes())), Header: http.Header{}}, nil
		}
		if r.URL.Query().Get("iiextmetadatafilter") != "Artist|LicenseShortName" {
			t.Error("metadata filter missing")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
	})}
	w := httptest.NewRecorder()
	a.imagesAPI(w, httptest.NewRequest("GET", "/api/images/search?q=Nature", nil))
	var data struct{ Items []ImageChoice }
	if json.Unmarshal(w.Body.Bytes(), &data) != nil || len(data.Items) != 1 || data.Items[0].Author != "Artist" {
		t.Fatal(w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	a.imagesAPI(w, httptest.NewRequest("GET", "/api/images/preview?id="+data.Items[0].ID, nil))
	if w.Code != 200 || w.Header().Get("Content-Type") != "image/png" {
		t.Fatal(w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	a.imagesAPI(w, httptest.NewRequest("GET", "/api/images/preview?id=unknown&url=http://127.0.0.1", nil))
	if w.Code != 404 {
		t.Fatal("arbitrary preview accepted")
	}
	for _, raw := range []string{"http://upload.wikimedia.org/a", "https://evil.example/a", "https://u:p@upload.wikimedia.org/a"} {
		if wikiAssetURL(raw) {
			t.Fatal("unsafe source accepted", raw)
		}
	}
}
func Test49OoklaConversionConsentAndAsyncExecution(t *testing.T) {
	fixture := `{"type":"result","ping":{"latency":12.5,"jitter":1.2},"download":{"bandwidth":12500000},"upload":{"bandwidth":2500000},"server":{"name":"fixture","country":"Test"},"result":{"url":"https://www.speedtest.net/result/c/test"}}`
	r, e := parseSpeedResult([]byte(fixture))
	if e != nil || r.Download != 100 || r.Upload != 20 || r.Ping != 12.5 {
		t.Fatal("bytes/s conversion wrong", r, e)
	}
	if _, e := parseSpeedResult([]byte(`{"type":"error"}`)); e == nil {
		t.Fatal("failed test represented as result")
	}
	file := filepath.Join(t.TempDir(), "speedtest")
	os.WriteFile(file, []byte("#!/bin/sh\nprintf '%s' '"+fixture+"'\n"), 0700)
	t.Setenv("ARIA_SPEEDTEST_BIN", file)
	a := automaticApp(t)
	post := func(body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/api/speedtest/run", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		a.speedAPI(w, r)
		return w
	}
	if w := post(`{"acceptedTerms":false}`); w.Code != 400 {
		t.Fatal("terms silently accepted")
	}
	if w := post(`{"acceptedTerms":true}`); w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	for i := 0; i < 100; i++ {
		a.speedMu.Lock()
		done := !a.speed.Running
		state := a.speed
		a.speedMu.Unlock()
		if done {
			if state.Result == nil || state.Result.Download != 100 {
				t.Fatal(state)
			}
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if w := post(`{"acceptedTerms":true}`); w.Code != 429 {
		t.Fatal("rate limit missing", w.Code)
	}
}
func Test49PS5BridgeContainsPrivateDoHAndRejectsPublicBind(t *testing.T) {
	a, c, _ := dnsFixture46(t)
	a.mu.Lock()
	a.state.Settings.PublicURL = "https://panel.example"
	a.mu.Unlock()
	w := httptest.NewRecorder()
	a.ps5BridgeExport(w, httptest.NewRequest("GET", "/api/dns/ps5-bridge?dns="+c.ID+"&lanIP=192.168.1.10", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "192.168.1.10") || !strings.Contains(w.Body.String(), c.Key) || !strings.Contains(w.Body.String(), "hijack-dns") {
		t.Fatal(w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	a.ps5BridgeExport(w, httptest.NewRequest("GET", "/api/dns/ps5-bridge?dns="+c.ID+"&lanIP=0.0.0.0", nil))
	if w.Code != 400 {
		t.Fatal("public listener allowed")
	}
}
