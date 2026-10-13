package gameroute

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func pairs(d, p int) []Pair {
	return []Pair{{Target: "https://publisher.example/", Direct: []Sample{{Status: d, MS: 40}, {Status: d, MS: 42}}, Proxy: []Sample{{Status: p, MS: 150}, {Status: p, MS: 148}}}}
}
func TestDecisionUsesStablePathsAndDoesNotCallServerErrorsSanctions(t *testing.T) {
	untried := Gameplay{Direct: "untried", Proxy: "untried"}
	for _, tc := range []struct {
		d, p             int
		state, suggested string
	}{{200, 200, "both-services", "direct"}, {403, 200, "proxy-service", "proxy"}, {451, 200, "proxy-service", "proxy"}, {403, 403, "services-unavailable", "keep"}, {401, 200, "inconclusive", "keep"}, {429, 200, "inconclusive", "keep"}, {503, 200, "inconclusive", "keep"}} {
		v := Decide(pairs(tc.d, tc.p), untried)
		if v.State != tc.state || v.Suggested != tc.suggested || v.Scope != "service" {
			t.Fatalf("%+v gives %+v", tc, v)
		}
	}
	p := pairs(200, 200)
	p[0].Direct[1].Error = "timeout"
	if v := Decide(p, untried); v.State != "inconclusive" || v.Suggested != "keep" {
		t.Fatal("unstable direct path falsely accepted", v)
	}
	if v := Decide(pairs(200, 200), Gameplay{Direct: "failed", Proxy: "passed"}); v.Suggested != "proxy" || v.Scope != "user-gameplay" {
		t.Fatal("actual gameplay ignored", v)
	}
	if v := Decide(pairs(200, 200), Gameplay{Direct: "failed", Proxy: "failed"}); v.Suggested != "keep" || v.State != "gameplay-unavailable" {
		t.Fatal("web health overrides failed gameplay", v)
	}
}
func TestProbeTLSAndRedirectBoundaries(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "https://elsewhere.invalid/", 302)
			return
		}
		w.WriteHeader(204)
	}))
	defer s.Close()
	p := Probe(context.Background(), []Target{{URL: s.URL}}, s.Client(), s.Client())
	if p[0].Direct[0].Status != 204 || p[0].Proxy[1].Status != 204 {
		t.Fatal(p)
	}
	strict := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}}
	p = Probe(context.Background(), []Target{{URL: s.URL}}, strict, s.Client())
	if p[0].Direct[0].Error != "tls" {
		t.Fatal("untrusted TLS accepted", p)
	}
	p = Probe(context.Background(), []Target{{URL: s.URL + "/redirect"}}, s.Client(), s.Client())
	if p[0].Direct[0].Error != "redirect" {
		t.Fatal("off-scope redirect followed", p)
	}
}
