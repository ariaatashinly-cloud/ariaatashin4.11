package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

func normalizeDirectManual(m ManualCreate) (ManualCreate, error) {
	m.Protocol = strings.ToLower(strings.TrimSpace(m.Protocol))
	m.Network = strings.ToLower(strings.TrimSpace(m.Network))
	m.Security = strings.ToLower(strings.TrimSpace(m.Security))
	m.UUID = strings.ToLower(strings.TrimSpace(m.UUID))
	m.Path = strings.TrimSpace(m.Path)
	if m.Network == "raw" {
		m.Network = "tcp"
	}
	if m.Protocol != "vless" && m.Protocol != "vmess" && m.Protocol != "trojan" && m.Protocol != "shadowsocks" {
		return m, fmt.Errorf("پروتکل دستی مستقیم باید VLESS، VMess، Trojan یا Shadowsocks باشد؛ TUIC/Hysteria2 را از الگوهای UDP همین فرم انتخاب کن")
	}
	switch m.Network {
	case "tcp", "ws", "xhttp", "grpc", "httpupgrade":
	default:
		return m, fmt.Errorf("انتقال مستقیم: TCP/RAW، WS، XHTTP، gRPC یا HTTPUpgrade")
	}
	if m.ListenPort < 1024 || m.ListenPort > 65535 {
		return m, fmt.Errorf("پورت شنود مستقیم باید ۱۰۲۴ تا ۶۵۵۳۵ باشد")
	}
	if m.Path != "" && !connectPathPattern.MatchString(m.Path) {
		return m, fmt.Errorf("Path باید مثل /connect/my-config-01/ باشد")
	}
	if m.Security == "" {
		m.Security = "tls"
	}
	if m.Security != "tls" && m.Security != "reality" && m.Security != "none" {
		return m, fmt.Errorf("Security معتبر نیست")
	}
	if m.Protocol == "shadowsocks" {
		if m.Network != "tcp" || m.Security != "none" {
			return m, fmt.Errorf("Shadowsocks مستقیم این فرم TCP/UDP با Security=none و رمزگذاری خود پروتکل دارد")
		}
		if m.Method == "" {
			m.Method = defaultShadowsocksMethod
		}
		if !validShadowsocksMethod(m.Method) {
			return m, fmt.Errorf("روش Shadowsocks معتبر نیست")
		}
	} else if m.Security == "none" {
		return m, fmt.Errorf("برای این پروتکل مستقیم TLS یا REALITY لازم است")
	} else if m.Method != "" {
		return m, fmt.Errorf("Method فقط برای Shadowsocks است")
	}
	if m.Security == "reality" && (m.Protocol != "vless" || (m.Network != "tcp" && m.Network != "xhttp" && m.Network != "grpc")) {
		return m, fmt.Errorf("REALITY این فرم با VLESS روی TCP، XHTTP یا gRPC قابل استفاده است")
	}
	if m.Flow != "" && (m.Flow != "xtls-rprx-vision" || m.Protocol != "vless" || m.Network != "tcp") {
		return m, fmt.Errorf("Vision فقط برای VLESS مستقیم TCP است")
	}
	if m.Network == "grpc" && m.Tuning.ALPN != "" && m.Tuning.ALPN != "auto" && m.Tuning.ALPN != "h2" {
		return m, fmt.Errorf("gRPC به ALPN=h2 نیاز دارد")
	}
	if m.Network == "httpupgrade" && m.Tuning.ALPN != "" && m.Tuning.ALPN != "auto" && m.Tuning.ALPN != "http/1.1" {
		return m, fmt.Errorf("HTTPUpgrade به HTTP/1.1 نیاز دارد")
	}
	if m.Network == "xhttp" {
		if m.Mode == "" {
			m.Mode = "auto"
		}
		if m.Mode != "auto" && m.Mode != "packet-up" && m.Mode != "stream-up" {
			return m, fmt.Errorf("Mode معتبر نیست")
		}
	} else if m.Mode != "" {
		return m, fmt.Errorf("Mode فقط برای XHTTP است")
	}
	password := m.Protocol == "trojan" || m.Protocol == "shadowsocks"
	if m.UUID != "" && (password || !uuidPattern.MatchString(m.UUID)) {
		return m, fmt.Errorf("UUID معتبر برای VLESS یا VMess لازم است")
	}
	if m.Password != "" && (!password || !validClientPassword(m.Password)) {
		return m, fmt.Errorf("رمز اتصال معتبر نیست")
	}
	var e error
	m.Endpoint, e = normalizeEndpoint(m.Endpoint)
	if e != nil {
		return m, e
	}
	m.Tuning.DownloadEndpoint, e = normalizeEndpoint(m.Tuning.DownloadEndpoint)
	if e != nil {
		return m, e
	}
	if m.Endpoint.Port != 0 && m.Endpoint.Port != m.ListenPort {
		return m, fmt.Errorf("پورت خروجی مستقیم باید با پورت شنود برابر باشد؛ برای NAT از فایل کلاینت استفاده کن")
	}
	m.Endpoint.Port = 0
	if e = validateTuning(m.Tuning, m.Network); e != nil {
		return m, e
	}
	return m, nil
}
func directManualRemark(s manualSpec) string {
	b, _ := json.Marshal(s)
	return "aria:direct-manual:" + base64.RawURLEncoding.EncodeToString(b)
}
func directManualInboundProfile(ib Inbound) (Profile, bool) {
	if len(ib.Remark) > 4096 {
		return Profile{}, false
	}
	b, e := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(ib.Remark, "aria:direct-manual:"))
	var s manualSpec
	if e != nil || json.Unmarshal(b, &s) != nil || !s.Direct {
		return Profile{}, false
	}
	p := s.profile()
	canonical, e := specFromProfile(p)
	if e != nil || canonical != s || ib.Protocol != p.Protocol || ib.Port != p.Port || ib.Listen != "0.0.0.0" {
		return Profile{}, false
	}
	var stream map[string]any
	if nestedJSON(ib.Stream, &stream) != nil || textField(stream, "network") != p.Network || textField(stream, "security") != p.Security {
		return Profile{}, false
	}
	t, _ := stream[p.Network+"Settings"].(map[string]any)
	if (p.Network == "ws" || p.Network == "xhttp" || p.Network == "httpupgrade") && textField(t, "path") != p.Path {
		return Profile{}, false
	}
	if p.Network == "grpc" && textField(t, "serviceName") != strings.TrimSuffix(strings.TrimPrefix(p.Path, "/connect/"), "/") {
		return Profile{}, false
	}
	if p.Security == "reality" {
		x, _ := stream["realitySettings"].(map[string]any)
		v := VPSConfig{PrivateKey: textField(x, "privateKey")}
		p.PublicKey = v.publicKey()
		if n, ok := x["serverNames"].([]any); ok && len(n) > 0 {
			p.ServerName, _ = n[0].(string)
		}
		if ids, ok := x["shortIds"].([]any); ok && len(ids) > 0 {
			p.ShortID, _ = ids[0].(string)
		}
	} else if p.Security == "tls" {
		x, _ := stream["tlsSettings"].(map[string]any)
		p.ServerName = textField(x, "serverName")
	}
	if p.Protocol == "shadowsocks" {
		var x map[string]any
		if nestedJSON(ib.Settings, &x) != nil || textField(x, "method") != p.Method || textField(x, "network") != "tcp,udp" {
			return Profile{}, false
		}
	}
	p.InboundID, p.Ready = ib.ID, ib.Enable
	return p, true
}
func directManualStream(p Profile, v VPSConfig) map[string]any {
	stream := map[string]any{"network": p.Network, "security": p.Security}
	switch p.Network {
	case "tcp":
		stream["tcpSettings"] = map[string]any{"header": map[string]any{"type": "none"}}
	case "ws", "httpupgrade":
		stream[p.Network+"Settings"] = map[string]any{"path": p.Path}
	case "xhttp":
		stream["xhttpSettings"] = map[string]any{"path": p.Path, "mode": p.XHTTPMode}
	case "grpc":
		stream["grpcSettings"] = map[string]any{"serviceName": strings.TrimSuffix(strings.TrimPrefix(p.Path, "/connect/"), "/"), "multiMode": false}
	}
	if p.Security == "tls" {
		alpn := []string{"h2", "http/1.1"}
		if p.Network == "ws" || p.Network == "httpupgrade" {
			alpn = []string{"http/1.1"}
		}
		if p.Network == "grpc" {
			alpn = []string{"h2"}
		}
		stream["tlsSettings"] = map[string]any{"serverName": v.ServerName, "minVersion": "1.2", "alpn": alpn, "certificates": []any{map[string]any{"certificateFile": v.CertFile, "keyFile": v.KeyFile}}}
	}
	if p.Security == "reality" {
		stream["realitySettings"] = map[string]any{"show": false, "target": v.RealityTarget + ":443", "serverNames": []string{v.RealityTarget}, "privateKey": v.PrivateKey, "shortIds": []string{v.ShortID}}
	}
	applyManualTuning(p, stream, false)
	return stream
}
func (a *App) ensureDirectManualProfile(ctx context.Context, e *EngineClient, s manualSpec) (Profile, error) {
	if a.cfg.Mode != "vps" {
		return Profile{}, fmt.Errorf("TCP/UDP مستقیم روی این هاست وب قابل شنود نیست؛ روی VPS با پورت عمومی اجرا کن")
	}
	if s.Key == "" {
		s.Key = "manual-" + randomToken(6)
	}
	automaticPath := s.Path == ""
	if s.Path == "" {
		s.Path = "/connect/" + s.Key + "/"
	}
	p := s.profile()
	canonical, err := specFromProfile(p)
	if err != nil || canonical != s {
		return p, fmt.Errorf("تنظیمات مستقیم معتبر نیست")
	}
	if p.Port == a.cfg.Port || p.Port == panelPort || p.Port == 443 || p.Port == 80 {
		return p, fmt.Errorf("پورت با پنل یا ورودی HTTPS تداخل دارد")
	}
	v := a.vpsSnapshot()
	if p.Security == "tls" {
		if err = v.certificateError(); err != nil {
			return p, err
		}
		if p.Endpoint.SNI != "" && p.Endpoint.SNI != v.ServerName {
			return p, fmt.Errorf("SNI باید با دامنهٔ گواهی VPS برابر باشد")
		}
		p.ServerName = v.ServerName
	} else if p.Security == "reality" {
		if p.Endpoint.SNI != "" && p.Endpoint.SNI != v.RealityTarget {
			return p, fmt.Errorf("SNI باید با مقصد REALITY برابر باشد")
		}
		p.ServerName = v.RealityTarget
		p.PublicKey = v.publicKey()
		p.ShortID = v.ShortID
	}
	all, err := e.inbounds(ctx)
	if err != nil {
		return p, err
	}
	for _, ib := range all {
		if ib.Port != p.Port {
			continue
		}
		old, ok := directManualInboundProfile(ib)
		if !ok {
			return p, fmt.Errorf("پورت %d در هسته رزرو است", p.Port)
		}
		prev, er := specFromProfile(old)
		prev.Key = s.Key
		if automaticPath {
			s.Path = prev.Path
			p.Path = prev.Path
		}
		if er != nil || prev != s || !old.Ready {
			return p, fmt.Errorf("پورت برای تنظیمات دیگری رزرو است")
		}
		return old, nil
	}
	settings := map[string]any{"clients": []any{}}
	if p.Protocol == "vless" {
		settings["decryption"] = "none"
	}
	if p.Protocol == "shadowsocks" {
		settings["method"] = p.Method
		settings["network"] = "tcp,udp"
	}
	body := map[string]any{"remark": directManualRemark(s), "enable": true, "listen": "0.0.0.0", "port": p.Port, "protocol": p.Protocol, "settings": marshalString(settings), "streamSettings": marshalString(directManualStream(p, v)), "sniffing": marshalString(map[string]any{"enabled": p.Tuning.Sniffing == "route", "routeOnly": true, "destOverride": []string{"http", "tls"}}), "up": 0, "down": 0, "total": 0, "expiryTime": 0}
	var added Inbound
	if err = e.call(ctx, "POST", "/panel/api/inbounds/add", body, &added); err != nil {
		return p, err
	}
	p.InboundID, p.Ready = added.ID, true
	return p, nil
}
func xrayDirectManualOutbound(p Profile, c map[string]any, origin string) map[string]any {
	if !p.Direct || !p.Manual {
		return nil
	}
	address, _, _ := publicEndpoint(origin)
	if p.Endpoint.Address != "" {
		address = p.Endpoint.Address
	}
	user := map[string]any{"id": textField(c, "id")}
	settings := map[string]any{"vnext": []any{map[string]any{"address": address, "port": p.Port, "users": []any{user}}}}
	switch p.Protocol {
	case "vless":
		user["encryption"] = "none"
		if p.Flow != "" {
			user["flow"] = p.Flow
		}
	case "vmess":
		user["security"] = "auto"
	case "trojan":
		settings = map[string]any{"servers": []any{map[string]any{"address": address, "port": p.Port, "password": textField(c, "password")}}}
	case "shadowsocks":
		settings = map[string]any{"servers": []any{map[string]any{"address": address, "port": p.Port, "method": p.Method, "password": textField(c, "password")}}}
	}
	stream := directManualStream(p, VPSConfig{})
	delete(stream, "tlsSettings")
	delete(stream, "realitySettings")
	if p.Security == "tls" {
		alpn := []string{"h2", "http/1.1"}
		if p.Network == "ws" || p.Network == "httpupgrade" {
			alpn = []string{"http/1.1"}
		}
		if p.Network == "grpc" {
			alpn = []string{"h2"}
		}
		stream["tlsSettings"] = map[string]any{"serverName": p.ServerName, "fingerprint": "chrome", "alpn": alpn}
	}
	if p.Security == "reality" {
		stream["realitySettings"] = map[string]any{"serverName": p.ServerName, "fingerprint": "chrome", "password": p.PublicKey, "shortId": p.ShortID}
	}
	if p.Network == "ws" || p.Network == "httpupgrade" {
		t := stream[p.Network+"Settings"].(map[string]any)
		if p.Endpoint.Host != "" {
			t["headers"] = map[string]any{"Host": p.Endpoint.Host}
		}
	}
	applyManualTuning(p, stream, true)
	return map[string]any{"tag": p.Key, "protocol": p.Protocol, "settings": settings, "streamSettings": stream}
}
