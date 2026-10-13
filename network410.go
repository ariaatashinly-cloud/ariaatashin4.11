package main

import (
	"context"
	"encoding/json"
	"fmt"
	"launcher/internal/cdnscan"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

type CDNScanState struct {
	mu      sync.Mutex
	Running bool
	Started int64
	Report  cdnscan.Report
	Cancel  context.CancelFunc
}

func (a *App) scanJob(route, input string, count int) (cdnscan.Job, error) {
	s := a.snapshot().Settings
	u, e := url.Parse(s.PublicURL)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" {
		return cdnscan.Job{}, fmt.Errorf("دامنهٔ HTTPS پنل را تنظیم کن")
	}
	host, sni := u.Hostname(), u.Hostname()
	port := 443
	if route != "" {
		found := false
		for _, r := range a.edgeSnapshot().Routes {
			if r.ID == route && r.Enabled && r.Verified {
				host, sni, port = r.Endpoint.Host, r.Endpoint.SNI, r.Endpoint.Port
				found = true
				break
			}
		}
		if !found {
			return cdnscan.Job{}, fmt.Errorf("مسیر باید فعال و تأییدشده باشد")
		}
	}
	ips, e := cdnscan.Candidates(input, count)
	if e != nil {
		return cdnscan.Job{}, e
	}
	j := cdnscan.Job{Host: host, SNI: sni, Port: port, Identity: a.edgeSnapshot().Identity, IPs: ips, Repeats: 3, TimeoutMS: 3000, Workers: 4}
	return j, cdnscan.ValidJob(j)
}
func (a *App) scanAPI(w http.ResponseWriter, r *http.Request) {
	st := &a.cdnScan
	if r.Method == "GET" && r.URL.Path == "/api/cdn-scan" {
		st.mu.Lock()
		d := map[string]any{"running": st.Running, "started": st.Started, "report": st.Report, "scope": "panel-server", "rangesChecked": "2026-10-12", "ranges": cdnscan.Ranges, "note": "نتیجهٔ سرور، شبکهٔ گوشی را تأیید نمی‌کند. ابزار دستگاه خودت را دانلود کن و گزارشش را وارد کن."}
		st.mu.Unlock()
		jsonReply(w, 200, d)
		return
	}
	if r.Method != "POST" {
		apiError(w, 405, "POST required")
		return
	}
	if r.URL.Path == "/api/cdn-scan/stop" {
		st.mu.Lock()
		if st.Cancel != nil {
			st.Cancel()
		}
		st.mu.Unlock()
		jsonReply(w, 200, map[string]bool{"ok": true})
		return
	}
	if r.URL.Path == "/api/cdn-scan/import" {
		var v cdnscan.Report
		if readBody(w, r, &v, 256<<10) != nil || v.Version != 1 || v.Scope != "client-device" || cdnscan.ValidJob(v.Job) != nil || v.Job.Identity != a.edgeSnapshot().Identity || len(v.Results) > 128 {
			apiError(w, 400, "گزارش معتبر ابزار دستگاه مربوط به همین پنل لازم است")
			return
		}
		for _, x := range v.Results {
			if !cdnscan.Allowed(x.IP) || x.Port != v.Job.Port || x.MedianMS < 0 || x.Attempts < 1 || x.Attempts > 5 || x.Successes < 0 || x.Successes > x.Attempts {
				apiError(w, 400, "نتیجهٔ اسکن معتبر نیست")
				return
			}
		}
		st.mu.Lock()
		if st.Running {
			st.mu.Unlock()
			apiError(w, 409, "ابتدا اسکن سرور را متوقف کن")
			return
		}
		st.Report = v
		st.mu.Unlock()
		jsonReply(w, 200, map[string]bool{"ok": true})
		return
	}
	var in struct {
		Route string `json:"route"`
		IPs   string `json:"ips"`
		Count int    `json:"count"`
	}
	if readBody(w, r, &in, 8192) != nil {
		apiError(w, 400, "فرم اسکن معتبر نیست")
		return
	}
	if in.Count == 0 {
		in.Count = 24
	}
	j, e := a.scanJob(in.Route, in.IPs, in.Count)
	if e != nil {
		apiError(w, 400, e.Error())
		return
	}
	if r.URL.Path == "/api/cdn-scan/job" {
		jsonReply(w, 200, j)
		return
	}
	if r.URL.Path != "/api/cdn-scan/run" {
		apiError(w, 404, "scan action not found")
		return
	}
	st.mu.Lock()
	if st.Running {
		st.mu.Unlock()
		apiError(w, 409, "یک اسکن در حال اجرا است")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	st.Running = true
	st.Started = time.Now().Unix()
	st.Cancel = cancel
	st.Report = cdnscan.Report{Version: 1, Scope: "panel-server", At: st.Started, Job: j, Results: []cdnscan.Result{}}
	st.mu.Unlock()
	go func() {
		result := cdnscan.Scan(ctx, j, "panel-server", func(v cdnscan.Result) { st.mu.Lock(); st.Report.Results = append(st.Report.Results, v); st.mu.Unlock() })
		cancel()
		st.mu.Lock()
		st.Report = result
		st.Running = false
		st.Cancel = nil
		st.mu.Unlock()
	}()
	jsonReply(w, 202, map[string]bool{"running": true})
}
func (a *App) stopCDNScan() {
	s := &a.cdnScan
	s.mu.Lock()
	if s.Cancel != nil {
		s.Cancel()
	}
	s.mu.Unlock()
}
func (a *App) gamingDNSAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		apiError(w, 405, "POST required")
		return
	}
	var in struct {
		Preset string `json:"preset"`
	}
	if readBody(w, r, &in, 1024) != nil {
		apiError(w, 400, "تنظیم معتبر نیست")
		return
	}
	d := a.dns
	d.mu.Lock()
	data := d.data
	s := data.Settings
	switch in.Preset {
	case "balanced":
		s.ResolverMode = "adaptive"
		s.HedgeMS = 180
		s.TimeoutMS = 2500
		s.Cache = true
	case "responsive":
		s.ResolverMode = "adaptive"
		s.HedgeMS = 100
		s.TimeoutMS = 1800
		s.Cache = true
	case "conservative":
		s.ResolverMode = "ordered"
		s.HedgeMS = 180
		s.TimeoutMS = 4000
		s.Cache = true
	default:
		d.mu.Unlock()
		apiError(w, 400, "پروفایل بازی معتبر نیست")
		return
	}
	data.Settings = s
	if e := validateDNSSettings(s, a.cfg); e != nil {
		d.mu.Unlock()
		apiError(w, 400, e.Error())
		return
	}
	if atomicJSON(a.cfg.DataDir, "aria-dns.json", data) != nil {
		d.mu.Unlock()
		apiError(w, 500, "تنظیمات ذخیره نشد")
		return
	}
	d.data = data
	d.cache = map[string]dnsCacheEntry{}
	d.mu.Unlock()
	jsonReply(w, 200, a.dnsPublic())
}
func (a *App) resilienceExport410(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email     string `json:"email"`
		Profile   string `json:"profile"`
		Fragment  bool   `json:"fragment"`
		LengthMin int    `json:"lengthMin"`
		LengthMax int    `json:"lengthMax"`
		DelayMin  int    `json:"delayMin"`
		DelayMax  int    `json:"delayMax"`
	}
	if readBody(w, r, &in, 2048) != nil {
		apiError(w, 400, "فرم خروجی معتبر نیست")
		return
	}
	u, ok := a.findUser(in.Email)
	if !ok {
		apiError(w, 404, "کاربر پیدا نشد")
		return
	}
	var p Profile
	owned := false
	for _, l := range u.Links {
		if l.Profile == in.Profile {
			owned = true
		}
	}
	for _, v := range a.snapshot().Profiles {
		if v.Key == in.Profile {
			p = v
		}
	}
	if !owned || p.Key == "" || p.UDP {
		apiError(w, 400, "اتصال TCP همین کاربر را انتخاب کن؛ UDP از خروجی بازی sing-box استفاده کند")
		return
	}
	s := a.snapshot().Settings
	out := xrayCloudOutbound(p, u.Raw, s.PublicURL, s.Connection)
	if out == nil && p.Direct {
		p.Manual = true
		if p.Protocol == "vless" && p.Network == "tcp" {
			p.Flow = "xtls-rprx-vision"
		}
		if p.Protocol == "shadowsocks" && p.Method == "" {
			p.Method = defaultShadowsocksMethod
		}
		out = xrayDirectManualOutbound(p, u.Raw, s.PublicURL)
	}
	if out == nil {
		apiError(w, 400, "خروجی Xray برای این ترکیب در دسترس نیست")
		return
	}
	outs := []any{out}
	if in.Fragment {
		stream, _ := out["streamSettings"].(map[string]any)
		if stream["security"] != "tls" {
			apiError(w, 400, "این گزینهٔ Fragment برای TLS است؛ REALITY یا UDP را جدا بررسی کن")
			return
		}
		if in.LengthMin < 16 || in.LengthMax > 1500 || in.LengthMax < in.LengthMin || in.DelayMin < 1 || in.DelayMax > 100 || in.DelayMax < in.DelayMin {
			apiError(w, 400, "طول قطعه ۱۶ تا ۱۵۰۰ بایت و فاصله ۱ تا ۱۰۰ میلی‌ثانیه لازم است")
			return
		}
		sock, _ := stream["sockopt"].(map[string]any)
		if sock == nil {
			sock = map[string]any{}
			stream["sockopt"] = sock
		}
		sock["dialerProxy"] = "fragment-out"
		outs = append(outs, map[string]any{"tag": "fragment-out", "protocol": "freedom", "settings": map[string]any{"fragment": map[string]any{"packets": "tlshello", "length": fmt.Sprintf("%d-%d", in.LengthMin, in.LengthMax), "interval": fmt.Sprintf("%d-%d", in.DelayMin, in.DelayMax)}}, "streamSettings": map[string]any{"sockopt": map[string]any{"tcpNoDelay": true}}})
	}
	cfg := map[string]any{"log": map[string]any{"loglevel": "warning"}, "inbounds": []any{map[string]any{"tag": "socks-in", "listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": true}}}, "outbounds": outs}
	verified, e := a.checkXrayConfig(r.Context(), cfg)
	if e != nil {
		apiError(w, 400, e.Error())
		return
	}
	jsonReply(w, 200, map[string]any{"config": cfg, "verified": verified, "fragment": in.Fragment, "note": "روی دستگاه کاربر وارد شود. Fragment ممکن است اتصال بعضی شبکه‌ها را تغییر دهد و تأخیر اضافه کند؛ ابتدا خروجی ساده را با همان مقصد مقایسه کن. اتصال در قطع همهٔ مسیرهای خارجی ایجاد نمی‌کند."})
}
func (a *App) checkXrayConfig(ctx context.Context, cfg any) (bool, error) {
	bin := filepath.Join(a.cfg.EngineDir, "bin", "xray-linux-amd64")
	if _, e := os.Stat(bin); e != nil {
		return false, nil
	}
	b, _ := json.Marshal(cfg)
	f, e := os.CreateTemp("", "aria-check410-*.json")
	if e != nil {
		return false, e
	}
	defer os.Remove(f.Name())
	f.Chmod(0600)
	_, e = f.Write(b)
	f.Close()
	if e != nil {
		return false, e
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if exec.CommandContext(ctx, bin, "run", "-test", "-config", f.Name()).Run() != nil {
		return false, fmt.Errorf("Xray این تنظیمات را نپذیرفت")
	}
	return true, nil
}
func (a *App) previewDirectManual(w http.ResponseWriter, r *http.Request, m ManualCreate) {
	if a.cfg.Mode != "vps" {
		apiError(w, 409, "پورت مستقیم نیازمند نصب VPS است؛ گزینه‌های وب در همین هاست کار می‌کنند")
		return
	}
	if m.Path == "" {
		m.Path = "/connect/preview-config-01/"
	}
	p := m.spec("manual-000000000000").profile()
	v := a.vpsSnapshot()
	if p.Security == "tls" {
		if e := v.certificateError(); e != nil {
			apiError(w, 409, e.Error())
			return
		}
		p.ServerName = v.ServerName
	} else {
		p.ServerName = v.RealityTarget
		p.PublicKey = v.publicKey()
		p.ShortID = v.ShortID
	}
	c := map[string]any{"id": m.UUID, "password": m.Password, "email": "preview", "flow": m.Flow}
	if c["id"] == "" {
		c["id"] = "00000000-0000-4000-8000-000000000001"
	}
	if c["password"] == "" {
		c["password"] = "preview-only-change-me"
	}
	settings := map[string]any{"clients": []any{c}}
	if p.Protocol == "vless" {
		settings["decryption"] = "none"
	}
	if p.Protocol == "shadowsocks" {
		settings["method"] = p.Method
		c["method"] = p.Method
		settings["network"] = "tcp,udp"
	}
	stream := directManualStream(p, v)
	server := map[string]any{"log": map[string]any{"loglevel": "warning"}, "inbounds": []any{map[string]any{"listen": "0.0.0.0", "port": p.Port, "protocol": p.Protocol, "settings": settings, "streamSettings": stream}}, "outbounds": []any{map[string]any{"protocol": "freedom"}}}
	client := map[string]any{"inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": 10808, "protocol": "socks"}}, "outbounds": []any{xrayDirectManualOutbound(p, c, a.snapshot().Settings.PublicURL)}}
	verified, e := a.checkXrayConfig(r.Context(), server)
	if e == nil {
		_, e = a.checkXrayConfig(r.Context(), client)
	}
	if e != nil {
		apiError(w, 400, e.Error())
		return
	}
	if x, ok := stream["realitySettings"].(map[string]any); ok {
		x["privateKey"] = "<private-key-on-server>"
	}
	jsonReply(w, 200, map[string]any{"server": server, "client": client, "verified": verified, "note": "پیش‌نمایش نحو؛ بازبودن فایروال و دسترسی اینترنت دستگاه جدا آزمایش شود. کلید خصوصی سرور از نمایش حذف شده است."})
}
