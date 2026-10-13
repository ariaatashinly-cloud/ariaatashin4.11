//go:build integration

package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestNative411PoolProbeCarriesTrafficAndRejectsWrongCredential(t *testing.T) {
	engine := os.Getenv("ARIA_TEST_ENGINE_DIR")
	if engine == "" {
		t.Skip("set ARIA_TEST_ENGINE_DIR")
	}
	bin := filepath.Join(engine, "bin", "xray-linux-amd64")
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer web.Close()
	a := testApp(t)
	a.cfg.EngineDir = engine
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	server := map[string]any{"log": map[string]string{"loglevel": "none"}, "inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": port, "protocol": "shadowsocks", "settings": map[string]any{"method": "aes-128-gcm", "password": "native-pool-fixture", "network": "tcp"}}}, "outbounds": []any{map[string]any{"protocol": "freedom", "settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow", "ip": []string{"127.0.0.1/32"}}, map[string]any{"action": "block"}}}}}}
	path := filepath.Join(t.TempDir(), "server.json")
	if e = os.WriteFile(path, []byte(marshalString(server)), 0600); e != nil {
		t.Fatal(e)
	}
	cmd := exec.CommandContext(ctx, bin, "run", "-config", path)
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	ready := false
	for i := 0; i < 60; i++ {
		c, e := net.DialTimeout("tcp", addr, 40*time.Millisecond)
		if e == nil {
			c.Close()
			ready = true
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	if !ready {
		t.Fatal("native fixture did not start")
	}
	uri := "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:native-pool-fixture")) + "@" + addr
	out, _, e := poolOutbound(uri)
	if e != nil {
		t.Fatal(e)
	}
	if _, state := a.runPoolProbe(ctx, bin, out, []string{web.URL}); state != "ok" {
		t.Fatal("live SOCKS -> SS -> HTTP probe failed", state)
	}
	uri = "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:wrong-secret")) + "@" + addr
	out, _, e = poolOutbound(uri)
	if e != nil {
		t.Fatal(e)
	}
	if _, state := a.runPoolProbe(ctx, bin, out, []string{web.URL}); state != "down" {
		t.Fatal("open TCP port with wrong credential was accepted", state)
	}
}

func TestNative411PoolProbeSyntaxMatrix(t *testing.T) {
	engine := os.Getenv("ARIA_TEST_ENGINE_DIR")
	if engine == "" {
		t.Skip("set ARIA_TEST_ENGINE_DIR")
	}
	a := testApp(t)
	a.cfg.EngineDir = engine
	for _, proto := range []string{"vless", "vmess", "trojan"} {
		for _, network := range []string{"tcp", "ws", "xhttp", "grpc", "httpupgrade"} {
			p := Profile{Key: "probe", Protocol: proto, Network: network, Security: "tls", Direct: true, Manual: true, Port: 443, ServerName: "public.example", Path: "/connect/probe/", XHTTPMode: "auto", Endpoint: LinkEndpoint{Address: "public.example"}}
			c := map[string]any{"id": "00000000-0000-4000-8000-000000000001", "password": "native-pool-fixture"}
			out := xrayDirectManualOutbound(p, c, "https://public.example")
			cfg := map[string]any{"outbounds": []any{out}}
			ok, e := a.checkXrayConfig(context.Background(), cfg)
			if e != nil || !ok {
				t.Fatal(proto, network, e)
			}
		}
	}
}
