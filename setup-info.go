package main

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

func (a *App) setupInfo(w http.ResponseWriter, r *http.Request) {
	s := a.dns.dataSettings()
	a.dns.mu.Lock()
	active := a.dns.active
	a.dns.mu.Unlock()
	ip := s.SmartIP
	if ip == "" {
		ip = a.exitLocation().IP
	}
	_, port, _ := net.SplitHostPort(s.DNSListen)
	jsonReply(w, 200, map[string]any{"mode": a.cfg.Mode, "dnsEnabled": s.Enabled, "classicConfigured": s.ClassicEnabled, "classicListening": active.ClassicEnabled && port == "53", "dnsIPCandidate": ip, "dnsPort": port, "publicHTTPS": strings.HasPrefix(a.snapshot().Settings.PublicURL, "https://"), "certificate": a.publicVPS(), "note": "IP خروجی ممکن است پشت NAT باشد؛ بازبودن TCP/UDP پورت ۵۳ باید از شبکهٔ کنسول آزموده شود. PS5 آدرس IP DNS معمولی می‌گیرد؛ لینک خصوصی DoH را در آن وارد نکن."})
}
func (a *App) ps5BridgeExport(w http.ResponseWriter, r *http.Request) {
	c, ok := a.dnsClientByID(r.URL.Query().Get("dns"))
	if !ok || !dnsClientActive(c) || !a.dns.dataSettings().Enabled {
		apiError(w, 409, "یک حساب DNS فعال انتخاب کن")
		return
	}
	ip := net.ParseIP(r.URL.Query().Get("lanIP"))
	if ip == nil || ip.To4() == nil || !ip.IsPrivate() {
		apiError(w, 400, "IPv4 خصوصی همان رایانه یا روتر خانه لازم است؛ مثلاً 192.168.1.10")
		return
	}
	doh, e := a.dnsURL(c, r.URL.Query().Get("dnsRoute"))
	if e != nil {
		apiError(w, 409, e.Error())
		return
	}
	config, e := ps5BridgeConfig(doh, ip.String())
	if e != nil {
		apiError(w, 400, e.Error())
		return
	}
	jsonReply(w, 200, map[string]any{"config": config, "primaryDNS": ip.String(), "secondaryDNS": ip.String(), "note": "این فایل را با sing-box 1.14 روی همان رایانه/روتر خانه اجرا کن؛ دستگاه باید روشن بماند و IP ثابت محلی و TCP/UDP پورت ۵۳ داشته باشد. سپس این IP را در DNS دستی PS5 بگذار. این پل فقط DNS است و ترافیک مسابقه را تونل نمی‌کند."})
}
func ps5BridgeConfig(doh, lanIP string) (map[string]any, error) {
	u, e := url.Parse(doh)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" {
		return nil, fmt.Errorf("HTTPS DoH required")
	}
	port := 443
	if u.Port() != "" {
		port, e = parsePort(u.Port())
		if e != nil {
			return nil, e
		}
	}
	return map[string]any{"log": map[string]string{"level": "warn"}, "inbounds": []any{map[string]any{"type": "direct", "tag": "lan-dns", "listen": lanIP, "listen_port": 53}}, "outbounds": []any{map[string]any{"type": "direct", "tag": "direct", "domain_resolver": "bootstrap"}}, "dns": map[string]any{"servers": []any{map[string]any{"type": "local", "tag": "bootstrap"}, map[string]any{"type": "https", "tag": "personal", "server": u.Hostname(), "server_port": port, "path": u.EscapedPath(), "tls": map[string]any{"enabled": true, "server_name": u.Hostname()}, "domain_resolver": "bootstrap", "detour": "direct"}}, "final": "personal", "strategy": "ipv4_only"}, "route": map[string]any{"default_domain_resolver": "bootstrap", "rules": []any{map[string]any{"source_ip_cidr": []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}, "invert": true, "action": "reject"}, map[string]any{"action": "sniff", "sniffer": []string{"dns"}}, map[string]any{"protocol": "dns", "action": "hijack-dns"}, map[string]any{"action": "reject"}}}}, nil
}
