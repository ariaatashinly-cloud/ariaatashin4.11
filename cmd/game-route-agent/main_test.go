package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"launcher/internal/gameroute"
)

func agentFixture(t *testing.T) (*agent, *atomic.Int64) {
	t.Helper()
	puts := new(atomic.Int64)
	selected := "game-route"
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer controller-secret" {
			http.Error(w, "unauthorized", 401)
			return
		}
		if r.Method == "PUT" {
			var b struct{ Name string }
			json.NewDecoder(r.Body).Decode(&b)
			selected = b.Name
			puts.Add(1)
			w.WriteHeader(204)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"now": selected})
	}))
	t.Cleanup(controller.Close)
	service := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	t.Cleanup(service.Close)
	a := &agent{ctx: context.Background(), job: gameroute.Job{GameName: "Game", Targets: []gameroute.Target{{URL: service.URL}}, ReportURL: service.URL, ReportToken: strings.Repeat("b", 64), AutoService: true}, report: gameroute.Report{Selected: "proxy", Locked: true, Gameplay: gameroute.Gameplay{Direct: "untried", Proxy: "untried"}}, direct: service.Client(), proxy: service.Client(), controller: controller.URL, secret: "controller-secret", localSecret: "local-secret", tun: true}
	return a, puts
}
func TestPeriodicTestKeepsGameplayRouteLocked(t *testing.T) {
	a, puts := agentFixture(t)
	a.test(false)
	if puts.Load() != 0 || a.report.Selected != "proxy" || !a.report.Locked || a.report.Decision.Suggested != "direct" {
		t.Fatal("periodic test changed a playing client's exit", a.report)
	}
	a.test(true)
	if puts.Load() != 1 || a.report.Selected != "direct" || !a.report.Applied || !a.report.Locked {
		t.Fatal("explicit pre-game test did not apply real selector", a.report)
	}
}
func TestLocalControllerRequiresHostTokenAndSameOrigin(t *testing.T) {
	a, _ := agentFixture(t)
	for _, tc := range []struct {
		host, token, origin string
		status              int
	}{{"malicious.example:1234", "local-secret", "", 403}, {"127.0.0.1:1234", "wrong", "", 401}, {"127.0.0.1:1234", "local-secret", "https://other.example", 403}, {"127.0.0.1:1234", "local-secret", "http://127.0.0.1:1234", 200}} {
		r := httptest.NewRequest("GET", "http://"+tc.host+"/status", nil)
		r.Header.Set("Authorization", "Bearer "+tc.token)
		r.Header.Set("Origin", tc.origin)
		w := httptest.NewRecorder()
		a.serve(w, r)
		if w.Code != tc.status {
			t.Fatal(tc, w.Code)
		}
	}
	a.tun = false
	r := httptest.NewRequest("POST", "http://127.0.0.1:1234/action", strings.NewReader(`{"action":"confirm","route":"proxy","result":"passed"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer local-secret")
	w := httptest.NewRecorder()
	a.serve(w, r)
	if w.Code != 409 {
		t.Fatal("gameplay confirmed without an active game TUN", w.Code)
	}
}
