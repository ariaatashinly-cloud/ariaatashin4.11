package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"launcher/internal/gameroute"
)

func deviceFixture48(t *testing.T) (*App, DNSClient) {
	a, c, _ := dnsFixture46(t)
	a.mu.Lock()
	a.state.Settings.PublicURL = "https://panel.example"
	a.state.Users = []User{{Email: "game-customer", Enabled: true, Links: []Connection{{Profile: "vless-ws"}}, Raw: map[string]any{"id": newUUID()}}}
	a.mu.Unlock()
	c.Smart = false
	c.Presets = []string{"rainbow-six"}
	c.GameRoutes = map[string]string{"rainbow-six": "direct"}
	a.dns.data.Clients = []DNSClient{c}
	a.dns.data.Settings.Enabled = true
	return a, c
}
func kit48(t *testing.T, a *App, c DNSClient) gameroute.Job {
	b, _ := json.Marshal(map[string]any{"params": map[string]string{"game": "rainbow-six", "email": "game-customer", "profile": "vless-ws", "dns": c.ID, "mode": "full", "platform": "windows", "dnsMode": "exit"}, "agentPlatform": "windows-amd64", "autoService": true})
	r := httptest.NewRequest("POST", "/api/gaming/test-kit", bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.gameTestKit(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	z, e := zip.NewReader(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len()))
	if e != nil {
		t.Fatal(e)
	}
	var j gameroute.Job
	for _, f := range z.File {
		if f.Name == "aria-game-test.json" {
			r, _ := f.Open()
			defer r.Close()
			if json.NewDecoder(r).Decode(&j) != nil {
				t.Fatal("bad private job")
			}
		}
	}
	if gameroute.ValidateJob(j) != nil || !j.AutoService {
		t.Fatal("invalid test kit", j.ID)
	}
	if !strings.Contains(string(w.Body.Bytes()), "game-route-agent.exe") {
		t.Fatal("missing runnable agent")
	}
	return j
}
func report48(j gameroute.Job) gameroute.Report {
	r := gameroute.Report{JobID: j.ID, GameID: j.GameID, Sequence: time.Now().UnixMilli(), Completed: time.Now().UnixMilli(), AgentVersion: gameroute.Version, Selected: "proxy", Locked: true, Gameplay: gameroute.Gameplay{Direct: "untried", Proxy: "untried"}}
	for _, t := range j.Targets {
		r.Pairs = append(r.Pairs, gameroute.Pair{Target: t.URL, Direct: []gameroute.Sample{{Status: 403, MS: 80}, {Status: 403, MS: 90}}, Proxy: []gameroute.Sample{{Status: 200, MS: 140}, {Status: 200, MS: 150}}})
	}
	return r
}
func postReport48(a *App, j gameroute.Job, r gameroute.Report, token string) *httptest.ResponseRecorder {
	b, _ := json.Marshal(r)
	req := httptest.NewRequest("POST", "/api/gaming/client-report", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)
	return w
}
func TestDeviceKitScopedReportPersistenceReplayAndRevoke(t *testing.T) {
	a, c := deviceFixture48(t)
	j := kit48(t, a, c)
	r := report48(j)
	if w := postReport48(a, j, r, strings.Repeat("x", 64)); w.Code != 401 {
		t.Fatal("wrong token accepted", w.Code)
	}
	r.Decision = gameroute.Decision{State: "sanctioned-everywhere"}
	if w := postReport48(a, j, r, j.ReportToken); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if a.deviceJobs[0].Report.Decision.State != "proxy-service" {
		t.Fatal("client labels trusted")
	}
	if w := postReport48(a, j, r, j.ReportToken); w.Code != 409 {
		t.Fatal("replay accepted", w.Code)
	}
	w := httptest.NewRecorder()
	a.gameTestsAPI(w, httptest.NewRequest("GET", "/api/gaming/tests", nil))
	if strings.Contains(w.Body.String(), j.ReportToken) || strings.Contains(w.Body.String(), "tokenHash") {
		t.Fatal("private token leaked")
	}
	if e := a.loadGameDeviceJobs(); e != nil || a.deviceJobs[0].Report.Decision.State != "proxy-service" {
		t.Fatal("result not persisted", e)
	}
	info, e := os.Stat(filepath.Join(a.cfg.DataDir, "aria-game-tests.json"))
	if e != nil || info.Mode().Perm() != 0600 {
		t.Fatal("report state mode", e)
	}
	r.Sequence++
	r.Pairs[0].Target = "https://wrong.example/"
	if w := postReport48(a, j, r, j.ReportToken); w.Code != 400 {
		t.Fatal("unexpected targets accepted", w.Code)
	}
	r = report48(j)
	r.Sequence += 10
	w = httptest.NewRecorder()
	a.gameTestsAPI(w, httptest.NewRequest("POST", "/api/gaming/tests/"+j.ID+"/revoke", strings.NewReader(`{}`)))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := postReport48(a, j, r, j.ReportToken); w.Code != 403 {
		t.Fatal("revocation ignored", w.Code)
	}
	for _, j := range a.deviceJobs {
		if len(j.TokenHash) != 64 {
			t.Fatal("raw token persistence")
		}
	}
}
func TestKitDoesNotMutateAccountDirectPolicyAndRefusesMobile(t *testing.T) {
	a, c := deviceFixture48(t)
	kit48(t, a, c)
	if a.dns.data.Clients[0].GameRoutes["rainbow-six"] != "direct" {
		t.Fatal("shared policy changed for another device")
	}
	b := `{"params":{"game":"rainbow-six","platform":"android"},"agentPlatform":"android-arm64"}`
	r := httptest.NewRequest("POST", "/api/gaming/test-kit", strings.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.gameTestKit(w, r)
	if w.Code != 400 {
		t.Fatal("unsupported mobile accepted", w.Code)
	}
	_, _ = io.Discard.Write(w.Body.Bytes())
}
