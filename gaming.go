package main

import (
	"fmt"
	"net/http"
	"net/url"
	"time"
)

func (a *App) gamingExport(w http.ResponseWriter, r *http.Request) {
	data, status, err := a.gamingExportData(r)
	if err != nil {
		apiError(w, status, err.Error())
		return
	}
	jsonReply(w, status, data)
}
func (a *App) gamingExportData(r *http.Request) (map[string]any, int, error) {
	u, ok := a.findUser(r.URL.Query().Get("email"))
	if !ok {
		return nil, 404, fmt.Errorf("%s", "کاربر Xray پیدا نشد")
	}
	if !u.Enabled || (u.Expiry > 0 && u.Expiry < time.Now().UnixMilli()) || (u.Quota > 0 && u.Up+u.Down >= u.Quota) {
		return nil, 409, fmt.Errorf("%s", "حساب اتصال باید فعال و دارای اعتبار باشد")
	}
	mode := r.URL.Query().Get("mode")
	if mode != "full" && mode != "games" && mode != "apps" {
		return nil, 400, fmt.Errorf("%s", "حالت دامنه، برنامه یا تونل کامل لازم است")
	}
	c, ok := a.dnsClientByID(r.URL.Query().Get("dns"))
	if !ok || !dnsClientActive(c) || !a.dns.dataSettings().Enabled {
		return nil, 409, fmt.Errorf("%s", "یک حساب DNS شخصی فعال انتخاب کن")
	}
	if c.Smart {
		return nil, 409, fmt.Errorf("%s", "برای تونل، حساب DNS را با Smart DNS خاموش بساز؛ رلهٔ Smart و تونل را همزمان روی یک دامنه فعال نکن")
	}
	if game := r.URL.Query().Get("game"); game != "" {
		if _, ok := gamePreset(game); !ok {
			return nil, 400, fmt.Errorf("%s", "بازی پیدا نشد")
		}
		c.Presets = []string{game}
		if r.URL.Query().Get("deviceTest") == "1" {
			c.GameRoutes = map[string]string{game: "proxy"}
			c.Domains = nil
		}
	}
	domains := clientGameDomains(c)
	if mode == "games" && len(domains) == 0 {
		return nil, 409, fmt.Errorf("%s", "ابتدا دامنه یا بستهٔ بازی را برای DNS انتخاب کن")
	}
	var p Profile
	found := false
	for _, link := range u.Links {
		for _, profile := range a.snapshot().Profiles {
			if profile.Key == link.Profile && profile.Key == r.URL.Query().Get("profile") {
				p = profile
				found = true
			}
		}
	}
	if !found {
		return nil, 404, fmt.Errorf("%s", "این پروفایل برای همین کاربر نیست")
	}
	if edgeID := r.URL.Query().Get("route"); edgeID != "" {
		found = false
		for _, e := range a.edgeSnapshot().Routes {
			if e.ID == edgeID && e.Enabled && e.Verified && edgeSupports(e, p) {
				p = profileForEdge(p, e)
				found = true
				break
			}
		}
		if !found {
			return nil, 409, fmt.Errorf("%s", "مسیر فعال، تأییدشده و سازگار با پروفایل لازم است")
		}
	}
	if p.Tuning.MuxConcurrency != 0 || p.Tuning.MaxEarlyData != 0 {
		return nil, 409, fmt.Errorf("%s", "برای این خروجی، WS با Mux و EarlyData صفر بساز")
	}
	settings := a.snapshot().Settings
	out := singBoxOutboundWithEndpoint(p, u.Raw, settings.PublicURL, settings.Connection)
	if out == nil {
		return nil, 409, fmt.Errorf("%s", "این انتقال در sing-box پشتیبانی نمی‌شود؛ VLESS WS یا اتصال مستقیم سازگار انتخاب کن")
	}
	out["tag"] = "game-proxy"
	out["domain_resolver"] = "bootstrap"
	if p.Protocol == "vless" || p.Protocol == "vmess" {
		out["packet_encoding"] = "xudp"
	}
	doh, e := a.dnsURL(c, r.URL.Query().Get("dnsRoute"))
	if e != nil {
		return nil, 409, fmt.Errorf("%s", e.Error())
	}
	config, e := gamingConfig(out, doh, domains, mode)
	if e != nil {
		return nil, 400, fmt.Errorf("%s", e.Error())
	}
	if err := a.addGameExitChoices(config, r); err != nil {
		return nil, 400, fmt.Errorf("%s", err.Error())
	}
	if err := applyGamePolicy(config, c, r); err != nil {
		return nil, 400, fmt.Errorf("%s", err.Error())
	}
	if r.URL.Query().Get("dnsMode") == "exit" {
		doh = "https://cloudflare-dns.com/dns-query"
	}
	return map[string]any{"config": config, "selectedGame": r.URL.Query().Get("game"), "location": a.exitLocation(), "mode": mode, "domains": domains, "dnsURL": doh, "note": "خروجی sing-box 1.14 با TUN است؛ در کلاینت سازگار اجازهٔ VPN/TUN بده. UDP در VLESS/VMess با XUDP روی تونل عبور می‌کند. حالت برنامه برای IP ثابت هم قواعد برنامه را به کار می‌گیرد؛ کنسول/iOS یا بازی بدون نام برنامه به تونل کامل نیاز دارد. بازی مستقیم از مسیر معمولی می‌رود. URLTest کیفیت HTTP را می‌سنجد، نه پذیرش حساب یا UDP مسابقه. تأخیر و پذیرش منطقه تابع مسیر و بازی است."}, 200, nil
}
func gamingConfig(out map[string]any, doh string, domains []string, mode string) (map[string]any, error) {
	u, e := url.Parse(doh)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" {
		return nil, fmt.Errorf("HTTPS DNS required")
	}
	port := 443
	if u.Port() != "" {
		port, e = parsePort(u.Port())
		if e != nil {
			return nil, e
		}
	}
	dnsServer := map[string]any{"type": "https", "tag": "personal", "server": u.Hostname(), "server_port": port, "path": u.EscapedPath(), "tls": map[string]any{"enabled": true, "server_name": u.Hostname()}, "domain_resolver": "bootstrap", "detour": "game-proxy"}
	rules := []any{map[string]any{"action": "sniff"}, map[string]any{"protocol": "dns", "action": "hijack-dns"}, map[string]any{"ip_is_private": true, "action": "route", "outbound": "direct"}}
	final := "game-proxy"
	if mode == "games" {
		rules = append(rules, map[string]any{"domain_suffix": domains, "action": "route", "outbound": "game-proxy"})
		final = "direct"
	}
	return map[string]any{
		"log":       map[string]any{"level": "warn", "timestamp": true},
		"dns":       map[string]any{"servers": []any{map[string]any{"type": "local", "tag": "bootstrap"}, dnsServer}, "final": "personal", "strategy": "ipv4_only", "independent_cache": true},
		"inbounds":  []any{map[string]any{"type": "tun", "tag": "game-tun", "interface_name": "aria-game", "address": []string{"172.19.0.1/30"}, "mtu": 1400, "auto_route": true, "strict_route": true, "stack": "system"}},
		"outbounds": []any{out, map[string]any{"type": "direct", "tag": "direct", "domain_resolver": "bootstrap"}},
		"route":     map[string]any{"auto_detect_interface": true, "default_domain_resolver": "personal", "rules": rules, "final": final},
	}, nil
}
