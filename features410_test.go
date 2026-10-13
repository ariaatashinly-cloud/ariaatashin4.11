package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func Test410AdminCanLoginWhileCoreUnavailableAndCredentialsPersist(t *testing.T) {
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer core.Close()
	cfg := Config{DataDir: t.TempDir(), AdminUser: "admin", AdminPassword: "admin", PublicURL: "https://panel.example", Mode: "cloud", Port: 8080}
	a, e := NewApp(cfg, core.URL)
	if e != nil {
		t.Fatal(e)
	}
	request := func(body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		a.ServeHTTP(w, browserRequest("POST", "/api/login", cfg.PublicURL, body))
		return w
	}
	w := request(`{"username":"admin","password":"wrong"}`)
	if w.Code != 401 || strings.Contains(w.Body.String(), "هسته") {
		t.Fatal(w.Code, w.Body.String())
	}
	w = request(`{"username":"admin","password":"admin"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"coreReady":false`) {
		t.Fatal("core downtime blocked admin", w.Code, w.Body.String())
	}
	cookie := w.Result().Cookies()[0]
	var login struct {
		CSRF string `json:"csrf"`
	}
	json.Unmarshal(w.Body.Bytes(), &login)
	r := browserRequest("POST", "/api/account", cfg.PublicURL, `{"username":"owner","password":"new-password","currentPassword":"admin"}`)
	r.AddCookie(cookie)
	r.Header.Set("X-ATIA-CSRF", login.CSRF)
	w = httptest.NewRecorder()
	a.changeAccount(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	cfg.AdminPassword = "different-private-core-password"
	next, e := NewApp(cfg, core.URL)
	if e != nil || !next.validAccount("owner", "new-password") || next.validAccount("admin", "admin") {
		t.Fatal("account changed after restart/env change", e)
	}
}
func Test410Native2FAPolicyIsKeptDuringCoreDowntime(t *testing.T) {
	a := automaticApp(t)
	os.WriteFile(filepath.Join(a.cfg.DataDir, "x-ui.db"), []byte("fixture"), 0600)
	dir := t.TempDir()
	script := "#!/bin/sh\nprintf '%s' '[{\"key\":\"twoFactorEnable\",\"value\":\"true\"},{\"key\":\"twoFactorToken\",\"value\":\"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\"}]'\n"
	os.WriteFile(filepath.Join(dir, "sqlite3"), []byte(script), 0700)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	secret, e := a.nativeOTPSecret(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if nativeTOTP(secret, time.Unix(59, 0)) != "287082" {
		t.Fatal("RFC6238 six-digit result wrong")
	}
	if validNativeOTP(secret, "000000", time.Unix(59, 0)) {
		t.Fatal("wrong OTP accepted")
	}
	if !validNativeOTP(secret, "287082", time.Unix(59, 0)) {
		t.Fatal("correct OTP rejected")
	}
	w := httptest.NewRecorder()
	a.login(w, browserRequest("POST", "/api/login", a.cfg.PublicURL, `{"username":"admin","password":"Test-only-password-123"}`))
	if w.Code == 200 {
		t.Fatal("2FA bypassed during downtime")
	}
}
func Test410ActivePanelSessionRenewsWithoutCore(t *testing.T) {
	a := automaticApp(t)
	a.sessions["fixture"] = session{CSRF: "csrf", Expires: time.Now().Add(time.Hour)}
	r := httptest.NewRequest("GET", "/api/session", nil)
	r.AddCookie(&http.Cookie{Name: "atia_session", Value: "fixture"})
	w := httptest.NewRecorder()
	a.renewPanelSession(w, r, a.sessions["fixture"], "https://panel.example")
	if len(w.Result().Cookies()) != 1 || time.Until(a.sessions["fixture"].Expires) < 11*time.Hour {
		t.Fatal("active session was not renewed")
	}
}
func Test410DirectManualMetadataAndCompatibility(t *testing.T) {
	a := automaticApp(t)
	v := a.vpsSnapshot()
	v.ServerName = "vpn.example"
	v.CertFile = "/test.crt"
	v.KeyFile = "/test.key"
	for _, proto := range []string{"vless", "vmess", "trojan", "shadowsocks"} {
		for _, network := range []string{"tcp", "ws", "xhttp", "grpc", "httpupgrade"} {
			if proto == "shadowsocks" && network != "tcp" {
				continue
			}
			m := ManualCreate{Direct: true, Protocol: proto, Network: network, ListenPort: 12001, Security: "tls", Path: "/connect/direct-test-01/"}
			if proto == "shadowsocks" {
				m.Security = "none"
				m.Method = "aes-128-gcm"
			}
			m, e := normalizeManual(m)
			if e != nil {
				t.Fatal(e)
			}
			spec := m.spec("manual-abcdef123456")
			p := spec.profile()
			stream := directManualStream(p, v)
			settings := map[string]any{"method": m.Method, "network": "tcp,udp"}
			ib := Inbound{ID: 1, Remark: directManualRemark(spec), Listen: "0.0.0.0", Port: m.ListenPort, Protocol: m.Protocol, Enable: true, Settings: json.RawMessage(marshalString(settings)), Stream: json.RawMessage(marshalString(stream))}
			loaded, ok := inboundProfile(ib)
			if !ok || !loaded.Manual || !loaded.Direct {
				t.Fatal("direct metadata lost", proto, network)
			}
			saved, e := specFromProfile(loaded)
			if e != nil || saved != spec {
				t.Fatal("direct backup metadata drift", e)
			}
			if xrayCloudOutbound(loaded, map[string]any{"id": "fixture", "password": "fixture-password"}, "https://vpn.example", LinkEndpoint{}) == nil {
				t.Fatal("Xray export omitted direct connection")
			}
			ib.Port++
			if _, ok = inboundProfile(ib); ok {
				t.Fatal("port metadata tampering accepted")
			}
		}
	}
	for _, m := range []ManualCreate{{Direct: true, Protocol: "trojan", Network: "tcp", Security: "reality", ListenPort: 12001}, {Direct: true, Protocol: "vless", Network: "grpc", Security: "tls", Flow: "xtls-rprx-vision", ListenPort: 12001}, {Protocol: "vless", Network: "tcp"}, {Direct: true, Protocol: "vless", Network: "tcp", Security: "none", ListenPort: 12001}} {
		if _, e := normalizeManual(m); e == nil {
			t.Fatal("unsupported combination accepted", m)
		}
	}
}
func Test410DNSLinkAndGamingProfilePreserveAccounts(t *testing.T) {
	a, c, _ := dnsFixture46(t)
	a.state.Settings.PublicURL = "https://panel.example"
	w := httptest.NewRecorder()
	a.dnsAPI(w, httptest.NewRequest("GET", "/api/dns/export?id="+c.ID, nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "https://panel.example/dns-query/") {
		t.Fatal(w.Code, w.Body.String())
	}
	before, _ := json.Marshal(a.dns.data.Clients)
	w = httptest.NewRecorder()
	a.gamingDNSAPI(w, browserRequest("POST", "/api/dns/gaming", "https://panel.example", `{"preset":"responsive"}`))
	after, _ := json.Marshal(a.dns.data.Clients)
	if w.Code != 200 || string(before) != string(after) || a.dns.data.Settings.HedgeMS != 100 {
		t.Fatal("gaming preset modified accounts", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "dohURL") {
		t.Fatal("DNS link missing from card data")
	}
}
