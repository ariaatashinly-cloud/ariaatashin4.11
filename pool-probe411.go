package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

func decodePool64(s string) ([]byte, error) {
	for _, e := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := e.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("base64 معتبر نیست")
}

// Only a generated proxy outbound is run. Arbitrary JSON, URLs, routing rules,
// insecure TLS, extra/detour endpoints and user-supplied inbounds are not run.
func poolOutbound(raw string) (map[string]any, string, error) {
	if len(raw) > 16000 {
		return nil, "", fmt.Errorf("لینک بیش از حد بلند است")
	}
	p := Profile{Key: "pool-probe", Manual: true, Direct: true, Network: "tcp", Security: "none"}
	client := map[string]any{}
	host := ""
	port := 443
	if strings.HasPrefix(raw, "vmess://") {
		b, e := decodePool64(strings.TrimPrefix(raw, "vmess://"))
		var v map[string]any
		if e != nil || json.Unmarshal(b, &v) != nil {
			return nil, "", fmt.Errorf("VMess معتبر نیست")
		}
		host = textField(v, "add")
		port, _ = strconv.Atoi(fmt.Sprint(v["port"]))
		p.Protocol = "vmess"
		client["id"] = textField(v, "id")
		p.Network = textField(v, "net")
		if p.Network == "" {
			p.Network = "tcp"
		}
		if textField(v, "tls") == "tls" {
			p.Security = "tls"
		}
		p.ServerName = textField(v, "sni")
		p.Path = textField(v, "path")
		p.Endpoint.Host = textField(v, "host")
		if p.Network == "grpc" && p.Path == "" {
			p.Path = textField(v, "serviceName")
		}
		if aid := fmt.Sprint(v["aid"]); aid != "0" && aid != "" && aid != "<nil>" {
			return nil, "", fmt.Errorf("VMess legacy قابل بررسی خودکار نیست")
		}
	} else {
		u, e := url.Parse(raw)
		if e != nil || u.User == nil || u.Hostname() == "" {
			return nil, "", fmt.Errorf("لینک قابل آزمایش موجود نیست")
		}
		q := u.Query()
		host = u.Hostname()
		if u.Port() != "" {
			port, _ = strconv.Atoi(u.Port())
		}
		if q.Get("allowInsecure") == "1" || q.Get("allowInsecure") == "true" || q.Get("insecure") == "1" || q.Get("extra") != "" {
			return nil, "", fmt.Errorf("این لینک با TLS ناامن یا extra نیازمند بررسی دستی است")
		}
		p.Protocol = u.Scheme
		p.Security = q.Get("security")
		if p.Security == "" {
			p.Security = "none"
		}
		p.Network = q.Get("type")
		if p.Network == "" || p.Network == "raw" {
			p.Network = "tcp"
		}
		p.ServerName = q.Get("sni")
		p.Path = q.Get("path")
		if p.Network == "grpc" {
			p.Path = q.Get("serviceName")
		}
		p.Endpoint.Host = q.Get("host")
		p.PublicKey = q.Get("pbk")
		p.ShortID = q.Get("sid")
		p.Flow = q.Get("flow")
		p.XHTTPMode = q.Get("mode")
		switch p.Protocol {
		case "vless":
			client["id"] = u.User.Username()
		case "trojan":
			client["password"] = u.User.Username()
			if q.Get("security") == "" {
				p.Security = "tls"
			}
		case "ss":
			p.Protocol = "shadowsocks"
			p.Security = "none"
			if q.Get("plugin") != "" {
				return nil, "", fmt.Errorf("SS plugin در پایش پشتیبانی نمی‌شود")
			}
			credential := u.User.String()
			if !strings.Contains(credential, ":") {
				b, e := decodePool64(u.User.Username())
				if e != nil {
					return nil, "", e
				}
				credential = string(b)
			} else {
				pass, _ := u.User.Password()
				credential = u.User.Username() + ":" + pass
			}
			parts := strings.SplitN(credential, ":", 2)
			if len(parts) != 2 {
				return nil, "", fmt.Errorf("رمز SS قابل خواندن نیست")
			}
			p.Method = parts[0]
			client["password"] = parts[1]
			if !validShadowsocksMethod(p.Method) {
				return nil, "", fmt.Errorf("روش SS در پایش پشتیبانی نمی‌شود")
			}
		default:
			return nil, "", fmt.Errorf("پایش واقعی فعلاً VLESS، VMess، Trojan و SS است؛ UDP و پروتکل دیگر نامعلوم نمایش داده می‌شوند")
		}
	}
	if host == "" || port < 1 || port > 65535 {
		return nil, "", fmt.Errorf("مقصد اتصال معتبر نیست")
	}
	p.Port = port
	p.Endpoint.Address = host
	if p.ServerName == "" {
		p.ServerName = host
	}
	if p.XHTTPMode == "" {
		p.XHTTPMode = "auto"
	}
	if p.Network != "tcp" && p.Network != "ws" && p.Network != "xhttp" && p.Network != "grpc" && p.Network != "httpupgrade" {
		return nil, "", fmt.Errorf("انتقال در پایش پشتیبانی نمی‌شود")
	}
	if p.Security != "tls" && p.Security != "none" && p.Security != "reality" {
		return nil, "", fmt.Errorf("Security پشتیبانی نمی‌شود")
	}
	if p.Security == "reality" && p.Protocol != "vless" {
		return nil, "", fmt.Errorf("REALITY فقط برای VLESS")
	}
	if (p.Protocol == "vless" || p.Protocol == "vmess") && !uuidPattern.MatchString(textField(client, "id")) {
		return nil, "", fmt.Errorf("UUID معتبر نیست")
	}
	if p.Flow != "" && p.Flow != "xtls-rprx-vision" {
		return nil, "", fmt.Errorf("Flow معتبر نیست")
	}
	return xrayDirectManualOutbound(p, client, "https://"+net.JoinHostPort(host, strconv.Itoa(port))), host, nil
}
func pinPoolOutbound(ctx context.Context, out map[string]any, host string) error {
	ips, e := net.DefaultResolver.LookupIPAddr(ctx, host)
	if e != nil || len(ips) == 0 {
		return fmt.Errorf("DNS مقصد آزمایش پاسخ نداد")
	}
	for _, ip := range ips {
		if blockedPanelIP(ip.IP) && !privatePanelsAllowed() {
			return fmt.Errorf("آدرس خصوصی در آزمایش مجاز نیست")
		}
	}
	settings := out["settings"].(map[string]any)
	for _, k := range []string{"servers", "vnext"} {
		if rows, ok := settings[k].([]any); ok {
			for _, r := range rows {
				r.(map[string]any)["address"] = ips[0].IP.String()
			}
		}
	}
	return nil
}

var poolTestTargets = []string{"https://www.gstatic.com/generate_204", "https://cp.cloudflare.com/generate_204"}

func poolHTTPTest(ctx context.Context, cl *http.Client, target string) bool {
	req, _ := http.NewRequestWithContext(ctx, "GET", target, nil)
	resp, e := cl.Do(req)
	if e != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return resp.StatusCode == 204
}
func (a *App) probeSale(ctx context.Context, v SoldService) ProbeResult {
	bin := filepath.Join(a.cfg.EngineDir, "bin", "xray-linux-amd64")
	if _, e := os.Stat(bin); e != nil {
		return ProbeResult{State: "unknown", Note: "Xray برای آزمایش اتصال نصب نیست"}
	}
	// Both control destinations failing on the controller is an ambiguous
	// measurement, not evidence that every customer's connection has failed.
	control := &http.Client{Transport: a.nodeClient().Transport, Timeout: 3 * time.Second, CheckRedirect: noRedirect}
	targets := []string{}
	for _, target := range poolTestTargets {
		if poolHTTPTest(ctx, control, target) {
			targets = append(targets, target)
		}
	}
	if len(targets) == 0 {
		return ProbeResult{State: "unknown", Note: "اینترنت ناظر یا هر دو مقصد آزمایش در دسترس نیست؛ تعویض خودکار انجام نمی‌شود"}
	}
	supported := 0
	failed := false
	unknown := false
	for i, link := range v.Links {
		if i >= 3 {
			break
		}
		out, host, e := poolOutbound(link)
		if e != nil {
			unknown = true
			continue
		}
		if pinPoolOutbound(ctx, out, host) != nil {
			unknown = true
			continue
		}
		ms, r := a.runPoolProbe(ctx, bin, out, targets)
		if r == "ok" {
			return ProbeResult{State: "ok", MS: ms, Note: "عبور HTTPS از کانفیگ تأیید شد"}
		}
		if r == "unknown" {
			unknown = true
		} else {
			failed = true
		}
		supported++
	}
	if supported > 0 && failed && !unknown {
		return ProbeResult{State: "down", Note: "هیچ‌یک از حداکثر ۳ اتصال آزمایش‌شده ترافیک عبور نداد"}
	}
	return ProbeResult{State: "unknown", Note: "همهٔ اتصال‌ها قابل آزمایش نیستند یا آزمایش کامل نشد؛ از خطای پینگ نتیجهٔ قطعی گرفته نشد"}
}
func (a *App) runPoolProbe(ctx context.Context, bin string, out map[string]any, targets []string) (int64, string) {
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		return 0, "unknown"
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	cfg := map[string]any{"log": map[string]string{"loglevel": "none"}, "inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": false}}}, "outbounds": []any{out}}
	dir, e := os.MkdirTemp(a.cfg.DataDir, ".pool-probe-")
	if e != nil {
		return 0, "unknown"
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "client.json")
	b, _ := json.Marshal(cfg)
	if os.WriteFile(path, b, 0600) != nil {
		return 0, "unknown"
	}
	job, c := context.WithTimeout(ctx, 12*time.Second)
	defer c()
	if exec.CommandContext(job, bin, "run", "-test", "-config", path).Run() != nil {
		return 0, "unknown"
	}
	cmd := exec.CommandContext(job, bin, "run", "-config", path)
	if cmd.Start() != nil {
		return 0, "unknown"
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	ready := false
	for i := 0; i < 40; i++ {
		conn, e := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if e == nil {
			conn.Close()
			ready = true
			break
		}
		select {
		case <-job.Done():
			return 0, "unknown"
		case <-time.After(50 * time.Millisecond):
		}
	}
	if !ready {
		return 0, "unknown"
	}
	d, e := proxy.SOCKS5("tcp", addr, nil, &net.Dialer{Timeout: 4 * time.Second})
	if e != nil {
		return 0, "unknown"
	}
	cd, ok := d.(proxy.ContextDialer)
	if !ok {
		return 0, "unknown"
	}
	tr := &http.Transport{Proxy: nil, DialContext: cd.DialContext}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, Timeout: 4 * time.Second, CheckRedirect: noRedirect}
	started := time.Now()
	for _, target := range targets {
		if poolHTTPTest(job, cl, target) {
			return time.Since(started).Milliseconds(), "ok"
		}
	}
	if ctx.Err() != nil {
		return 0, "unknown"
	}
	return 0, "down"
}
