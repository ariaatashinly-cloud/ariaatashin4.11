package cdnscan

import (
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/net/proxy"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Build a fresh local client with one proxy outbound. User-supplied inbound,
// routing and API settings are never executed by the scanner.
func ValidateTunnel(ctx context.Context, xray string, raw []byte, ip string) (int64, error) {
	if !Allowed(ip) {
		return 0, fmt.Errorf("IP outside Cloudflare")
	}
	var cfg struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if json.Unmarshal(raw, &cfg) != nil {
		return 0, fmt.Errorf("Xray JSON required")
	}
	var out map[string]any
	for _, o := range cfg.Outbounds {
		p, _ := o["protocol"].(string)
		if p == "vless" || p == "vmess" || p == "trojan" || p == "shadowsocks" {
			if out != nil {
				return 0, fmt.Errorf("select a single connection JSON")
			}
			out = o
		}
	}
	if out == nil {
		return 0, fmt.Errorf("supported proxy outbound missing")
	}
	settings, _ := out["settings"].(map[string]any)
	stream, _ := out["streamSettings"].(map[string]any)
	if stream == nil || settings == nil {
		return 0, fmt.Errorf("outbound settings missing")
	}
	if stream["security"] != "tls" {
		return 0, fmt.Errorf("CDN requires TLS outbound")
	}
	sock, _ := stream["sockopt"].(map[string]any)
	if sock != nil {
		delete(sock, "dialerProxy")
	}
	for _, key := range []string{"vnext", "servers"} {
		if entries, ok := settings[key].([]any); ok {
			for _, v := range entries {
				if server, ok := v.(map[string]any); ok {
					server["address"] = ip
				}
			}
		}
	}
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		return 0, e
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	clean := map[string]any{"log": map[string]any{"loglevel": "none"}, "inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": false}}}, "outbounds": []any{out}}
	dir, e := os.MkdirTemp("", "aria-scan-")
	if e != nil {
		return 0, e
	}
	defer os.RemoveAll(dir)
	b, _ := json.Marshal(clean)
	path := filepath.Join(dir, "client.json")
	if e = os.WriteFile(path, b, 0600); e != nil {
		return 0, e
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, xray, "run", "-config", path)
	if e = cmd.Start(); e != nil {
		return 0, e
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	ready := false
	for i := 0; i < 60; i++ {
		c, e := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if e == nil {
			c.Close()
			ready = true
			break
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	if !ready {
		return 0, fmt.Errorf("Xray did not start")
	}
	d, e := proxy.SOCKS5("tcp", addr, nil, &net.Dialer{Timeout: 5 * time.Second})
	if e != nil {
		return 0, e
	}
	cd, ok := d.(proxy.ContextDialer)
	if !ok {
		return 0, fmt.Errorf("context dialer missing")
	}
	tr := &http.Transport{Proxy: nil, DialContext: cd.DialContext}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	start := time.Now()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://www.gstatic.com/generate_204", nil)
	resp, e := cl.Do(req)
	if e != nil {
		return 0, e
	}
	resp.Body.Close()
	if resp.StatusCode != 204 {
		return 0, fmt.Errorf("test destination returned %d", resp.StatusCode)
	}
	return time.Since(start).Milliseconds(), nil
}
