//go:build integration

package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestNative410DirectManualCreationTrafficAndReload(t *testing.T) {
	a, ctx := nativeTestApp(t)
	a.cfg.Mode = "vps"
	allowNativeTestLoopback(t, ctx, a.service)
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	m, e := normalizeManual(ManualCreate{Direct: true, Protocol: "shadowsocks", Network: "tcp", Security: "none", ListenPort: port, Method: "aes-128-gcm", Password: "Native-direct-password-410"})
	if e != nil {
		t.Fatal(e)
	}
	p, e := a.ensureManualProfile(ctx, a.service, m.spec(""))
	if e != nil {
		t.Fatal(e)
	}
	c := map[string]any{"id": newUUID(), "email": "aria-direct410", "comment": "direct fixture", "password": m.Password, "subId": randomToken(16), "enable": true, "totalGB": 0, "expiryTime": 0}
	if e = a.service.call(ctx, "POST", "/panel/api/clients/add", map[string]any{"client": c, "inboundIds": []int{p.InboundID}}, nil); e != nil {
		t.Fatal(e)
	}
	if e = a.refresh(ctx); e != nil {
		t.Fatal(e)
	}
	var actual Profile
	for _, v := range a.snapshot().Profiles {
		if v.Key == p.Key {
			actual = v
		}
	}
	if !actual.Direct || !actual.Ready || actual.Method != "aes-128-gcm" {
		t.Fatal("direct profile not published")
	}
	actual.Endpoint.Address = "127.0.0.1"
	probeManualTraffic(t, ctx, a.cfg.EngineDir, actual, c, "http://127.0.0.1")
	duplicate := m
	duplicate.Path = "/connect/different-path-01/"
	if _, e = a.ensureManualProfile(ctx, a.service, duplicate.spec("")); e == nil {
		t.Fatal("conflicting path reused port")
	}
	spec, e := specFromProfile(p)
	if e != nil {
		t.Fatal(e)
	}
	same, e := a.ensureManualProfile(ctx, a.service, spec)
	if e != nil || same.InboundID != p.InboundID {
		t.Fatal("saved manual identity did not reload", e)
	}
}
func TestNative410DirectAndFragmentSyntax(t *testing.T) {
	bin := os.Getenv("ARIA_TEST_ENGINE_DIR")
	if bin == "" {
		t.Skip("set ARIA_TEST_ENGINE_DIR")
	}
	a := automaticApp(t)
	a.cfg.EngineDir = bin
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if e := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert, "-subj", "/CN=vpn.example", "-days", "1").Run(); e != nil {
		t.Fatal(e)
	}
	v := a.vpsSnapshot()
	v.ServerName = "vpn.example"
	v.CertFile = cert
	v.KeyFile = key
	for _, proto := range []string{"vless", "vmess", "trojan", "shadowsocks"} {
		for _, network := range []string{"tcp", "ws", "xhttp", "grpc", "httpupgrade"} {
			if proto == "shadowsocks" && network != "tcp" {
				continue
			}
			m := ManualCreate{Direct: true, Protocol: proto, Network: network, Security: "tls", ListenPort: 12001, Path: "/connect/syntax-config-01/"}
			if proto == "shadowsocks" {
				m.Security = "none"
			}
			m, e := normalizeManual(m)
			if e != nil {
				t.Fatal(e)
			}
			p := m.spec("manual-012345abcdef").profile()
			p.ServerName = v.ServerName
			c := map[string]any{"id": newUUID(), "password": "syntax-test-password", "email": "fixture"}
			settings := map[string]any{"clients": []any{c}}
			if proto == "vless" {
				settings["decryption"] = "none"
			}
			if proto == "shadowsocks" {
				settings["method"] = m.Method
				c["method"] = m.Method
				settings["network"] = "tcp,udp"
			}
			server := map[string]any{"inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": p.Port, "protocol": proto, "settings": settings, "streamSettings": directManualStream(p, v)}}, "outbounds": []any{map[string]any{"protocol": "freedom"}}}
			if verified, e := a.checkXrayConfig(context.Background(), server); e != nil || !verified {
				t.Fatal("server syntax", proto, network, e)
			}
			client := map[string]any{"outbounds": []any{xrayDirectManualOutbound(p, c, "https://vpn.example")}}
			if verified, e := a.checkXrayConfig(context.Background(), client); e != nil || !verified {
				t.Fatal("client syntax", proto, network, e)
			}
		}
	}
	for _, n := range []string{"tcp", "xhttp", "grpc"} {
		m, e := normalizeManual(ManualCreate{Direct: true, Protocol: "vless", Network: n, Security: "reality", ListenPort: 12001, Path: "/connect/reality-syntax-01/"})
		if e != nil {
			t.Fatal(e)
		}
		p := m.spec("manual-012345abcdef").profile()
		p.ServerName = v.RealityTarget
		p.PublicKey = v.publicKey()
		p.ShortID = v.ShortID
		c := map[string]any{"id": newUUID()}
		cfg := map[string]any{"outbounds": []any{xrayDirectManualOutbound(p, c, "https://vpn.example")}}
		if _, e = a.checkXrayConfig(context.Background(), cfg); e != nil {
			t.Fatal("REALITY client", n, e)
		}
		cfg = map[string]any{"inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": p.Port, "protocol": "vless", "settings": map[string]any{"clients": []any{c}, "decryption": "none"}, "streamSettings": directManualStream(p, v)}}}
		if _, e = a.checkXrayConfig(context.Background(), cfg); e != nil {
			t.Fatal("REALITY server", n, e)
		}
	}
	a.state.Settings.PublicURL = "https://vpn.example"
	a.state.Profiles = []Profile{{Key: "vless-ws", Protocol: "vless", Network: "ws", Path: "/connect/fragment-test-01/"}}
	a.state.Users = []User{{Email: "fixture", Raw: map[string]any{"id": newUUID()}, Links: []Connection{{Profile: "vless-ws"}}}}
	w := httptest.NewRecorder()
	a.resilienceExport410(w, browserRequest("POST", "/api/resilience/export", "https://vpn.example", `{"email":"fixture","profile":"vless-ws","fragment":true,"lengthMin":100,"lengthMax":200,"delayMin":10,"delayMax":20}`))
	if w.Code != 200 {
		t.Fatal("fragment syntax", w.Code, w.Body.String())
	}
	var d map[string]any
	if json.Unmarshal(w.Body.Bytes(), &d) != nil || d["verified"] != true {
		t.Fatal("fragment not checked with real Xray")
	}
}
