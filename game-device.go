package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"launcher/internal/gameroute"
)

type GameDeviceJob struct {
	ID          string             `json:"id"`
	GameID      string             `json:"gameID"`
	Email       string             `json:"email"`
	DNSID       string             `json:"dnsID"`
	Mode        string             `json:"mode"`
	Created     int64              `json:"created"`
	Expires     int64              `json:"expires"`
	Revoked     bool               `json:"revoked"`
	TokenHash   string             `json:"tokenHash,omitempty"`
	Targets     []gameroute.Target `json:"targets"`
	AutoService bool               `json:"autoService"`
	Received    int64              `json:"received"`
	Report      *gameroute.Report  `json:"report,omitempty"`
}

func (a *App) loadGameDeviceJobs() error {
	a.deviceJobs = []GameDeviceJob{}
	b, e := os.ReadFile(filepath.Join(a.cfg.DataDir, "aria-game-tests.json"))
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	if json.Unmarshal(b, &a.deviceJobs) != nil || len(a.deviceJobs) > 128 {
		return fmt.Errorf("game device state invalid")
	}
	for _, j := range a.deviceJobs {
		if _, ok := gamePreset(j.GameID); !ok || len(j.TokenHash) != 64 || !strings.HasPrefix(j.ID, "gt-") {
			return fmt.Errorf("invalid game test identity")
		}
	}
	return nil
}
func serviceTargets(game string) []gameroute.Target {
	urls := map[string][]string{
		"rainbow-six":    {"https://www.ubisoft.com/", "https://www.ubisoftconnect.com/"},
		"clash-of-clans": {"https://supercell.com/", "https://clashofclans.com/"},
		"call-of-duty":   {"https://www.callofduty.com/", "https://www.activision.com/"},
		"cod-mobile":     {"https://www.callofduty.com/"},
		"battlefield":    {"https://www.ea.com/"},
		"marvel-rivals":  {"https://www.marvelrivals.com/"},
		"steam":          {"https://store.steampowered.com/"},
		"epic":           {"https://www.epicgames.com/"},
	}
	out := []gameroute.Target{}
	for _, u := range urls[game] {
		out = append(out, gameroute.Target{Name: "سرویس ناشر · ورود و مسابقه تأیید نشده", URL: u})
	}
	return out
}
func gameTokenHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func (a *App) gameTestsAPI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api/gaming/test-kit" && r.Method == "POST" {
		a.gameTestKit(w, r)
		return
	}
	a.deviceMu.Lock()
	defer a.deviceMu.Unlock()
	if r.URL.Path == "/api/gaming/tests" && r.Method == "GET" {
		out := append([]GameDeviceJob{}, a.deviceJobs...)
		for i := range out {
			out[i].TokenHash = ""
		}
		jsonReply(w, 200, map[string]any{"jobs": out, "now": time.Now().Unix(), "note": "آزمون از دستگاه کاربر گزارش می‌شود. دسترسی HTTP سرویس با ورود و مسابقه متفاوت است؛ گزارش قدیمی به اینترنت فعلی تعمیم داده نمی‌شود."})
		return
	}
	if r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/api/gaming/tests/") && strings.HasSuffix(r.URL.Path, "/revoke") {
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/gaming/tests/"), "/revoke")
		next := append([]GameDeviceJob{}, a.deviceJobs...)
		for i := range next {
			if next[i].ID == id {
				next[i].Revoked = true
				if e := atomicJSON(a.cfg.DataDir, "aria-game-tests.json", next); e != nil {
					apiError(w, 500, "ذخیره انجام نشد")
					return
				}
				a.deviceJobs = next
				jsonReply(w, 200, map[string]bool{"ok": true})
				return
			}
		}
		apiError(w, 404, "آزمون پیدا نشد")
		return
	}
	apiError(w, 405, "عملیات آزمون معتبر نیست")
}
func (a *App) gameTestKit(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Params        map[string]string `json:"params"`
		AgentPlatform string            `json:"agentPlatform"`
		AutoService   bool              `json:"autoService"`
	}
	if readBody(w, r, &in, 8192) != nil || len(in.Params) > 18 {
		apiError(w, 400, "فرم آزمون معتبر نیست")
		return
	}
	platforms := map[string]string{"windows-amd64": "game-route-agent-windows-amd64.exe", "linux-amd64": "game-route-agent-linux-amd64", "linux-arm64": "game-route-agent-linux-arm64", "darwin-arm64": "game-route-agent-darwin-arm64", "darwin-amd64": "game-route-agent-darwin-amd64"}
	bin, ok := platforms[in.AgentPlatform]
	if !ok {
		apiError(w, 400, "برنامهٔ همراه برای Windows، Linux یا macOS است؛ Android/iOS به کلاینت بومی جدا نیاز دارد")
		return
	}
	game, ok := gamePreset(in.Params["game"])
	if !ok {
		apiError(w, 400, "برای آزمون یک بازی مشخص انتخاب کن")
		return
	}
	if in.Params["exit"] == "auto" {
		apiError(w, 400, "برای آزمون دستگاه یک خروجی ثابت انتخاب کن تا مقایسهٔ دو مسیر و IP بازی ثابت بماند")
		return
	}
	if in.Params["platform"] != "windows" && in.Params["platform"] != "linux" && in.Params["platform"] != "macos" {
		apiError(w, 400, "این بسته روی رایانه اجرا می‌شود؛ دستگاه خروجی را رایانه انتخاب کن")
		return
	}
	if !strings.HasPrefix(in.AgentPlatform, in.Params["platform"]+"-") && !(in.Params["platform"] == "macos" && strings.HasPrefix(in.AgentPlatform, "darwin-")) {
		apiError(w, 400, "سیستم بسته و دستگاه خروجی یکسان باشند")
		return
	}
	q := url.Values{}
	for k, v := range in.Params {
		if len(k) > 24 || len(v) > 2048 {
			apiError(w, 400, "گزینه بیش از حد طولانی است")
			return
		}
		q.Set(k, v)
	}
	// A single selected game must be covered even if its DNS-account policy is
	// direct. The device's game-smart selector owns this private kit's choice.
	q.Set("deviceTest", "1")
	u := *r.URL
	u.RawQuery = q.Encode()
	req := r.Clone(r.Context())
	req.URL = &u
	data, status, e := a.gamingExportData(req)
	if e != nil {
		apiError(w, status, e.Error())
		return
	}
	origin, e := validatePublicURL(a.snapshot().Settings.PublicURL)
	if e != nil || origin.Scheme != "https" {
		apiError(w, 409, "برای گزارش امن دستگاه، آدرس HTTPS پنل را تنظیم کن")
		return
	}
	binary, e := fs.ReadFile(assets, "web/game-agent/"+bin)
	if e != nil {
		apiError(w, 503, "برنامهٔ همراه ساخته نشده؛ scripts/build-game-agent.sh را پیش از ساخت پنل اجرا کن")
		return
	}
	token := randomToken(32)
	now := time.Now().Unix()
	job := gameroute.Job{Version: 1, ID: "gt-" + randomToken(12), GameID: game.ID, GameName: game.Name, Mode: in.Params["mode"], Expires: now + 86400, ReportURL: strings.TrimRight(origin.String(), "/") + "/api/gaming/client-report", ReportToken: token, Targets: serviceTargets(game.ID), AutoService: in.AutoService, Config: data["config"].(map[string]any)}
	var buffer bytes.Buffer
	z := zip.NewWriter(&buffer)
	add := func(name string, body []byte, mode os.FileMode) error {
		h := &zip.FileHeader{Name: name, Method: zip.Deflate}
		h.SetMode(mode)
		f, e := z.CreateHeader(h)
		if e != nil {
			return e
		}
		_, e = f.Write(body)
		return e
	}
	b, _ := json.MarshalIndent(job, "", "  ")
	binName := "game-route-agent"
	if strings.HasPrefix(in.AgentPlatform, "windows-") {
		binName += ".exe"
	}
	files := []struct {
		name string
		body []byte
		mode os.FileMode
	}{{binName, binary, 0700}, {"aria-game-test.json", b, 0600}, {"README-FA.txt", []byte(gameAgentGuide(game.Name)), 0600}, {"start.sh", []byte("#!/bin/sh\nset -eu\ncd -- \"$(dirname -- \"$0\")\"\nchmod +x ./game-route-agent\nexec ./game-route-agent --job aria-game-test.json --sing-box ./sing-box --tun\n"), 0700}, {"start.cmd", []byte("@echo off\r\ncd /d \"%~dp0\"\r\ngame-route-agent.exe --job aria-game-test.json --sing-box sing-box.exe --tun\r\npause\r\n"), 0600}}
	for _, f := range files {
		if add(f.name, f.body, f.mode) != nil {
			apiError(w, 500, "بسته ساخته نشد")
			return
		}
	}
	if z.Close() != nil {
		apiError(w, 500, "بسته ساخته نشد")
		return
	}
	a.deviceMu.Lock()
	next := []GameDeviceJob{}
	for _, v := range a.deviceJobs {
		if v.Created > now-7*86400 {
			next = append(next, v)
		}
	}
	if len(next) >= 128 {
		a.deviceMu.Unlock()
		apiError(w, 409, "حداکثر ۱۲۸ آزمون در هفت روز؛ بستهٔ قدیمی را دوباره بساز یا منتظر حذف خودکار بمان")
		return
	}
	next = append(next, GameDeviceJob{ID: job.ID, GameID: job.GameID, Email: in.Params["email"], DNSID: in.Params["dns"], Mode: job.Mode, Created: now, Expires: job.Expires, TokenHash: gameTokenHash(token), Targets: job.Targets, AutoService: in.AutoService})
	e = atomicJSON(a.cfg.DataDir, "aria-game-tests.json", next)
	if e == nil {
		a.deviceJobs = next
	}
	a.deviceMu.Unlock()
	if e != nil {
		apiError(w, 500, "ذخیرهٔ آزمون انجام نشد")
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="aria-game-test-%s.zip"`, game.ID))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(200)
	_, _ = w.Write(buffer.Bytes())
}
func (a *App) gameClientReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		apiError(w, 405, "POST required")
		return
	}
	var report gameroute.Report
	if readBody(w, r, &report, 32768) != nil {
		apiError(w, 400, "invalid report")
		return
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if len(token) != 64 {
		apiError(w, 401, "invalid report token")
		return
	}
	a.deviceMu.Lock()
	defer a.deviceMu.Unlock()
	now := time.Now().Unix()
	next := append([]GameDeviceJob{}, a.deviceJobs...)
	for i, j := range next {
		if j.ID != report.JobID {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(j.TokenHash), []byte(gameTokenHash(token))) != 1 {
			break
		}
		if j.Revoked || j.Expires < now {
			apiError(w, 403, "report job expired or revoked")
			return
		}
		client, ok := a.dnsClientByID(j.DNSID)
		user, found := a.findUser(j.Email)
		if !ok || !dnsClientActive(client) || !found || !user.Enabled || (user.Expiry > 0 && user.Expiry < time.Now().UnixMilli()) || (user.Quota > 0 && user.Up+user.Down >= user.Quota) {
			apiError(w, 403, "account inactive")
			return
		}
		if report.GameID != j.GameID || gameroute.ValidateReport(report, j.Targets) != nil || report.Completed < j.Created*1000 || report.Completed > time.Now().Add(2*time.Minute).UnixMilli() {
			apiError(w, 400, "invalid measurements")
			return
		}
		if j.Report != nil && report.Sequence <= j.Report.Sequence {
			apiError(w, 409, "old report sequence")
			return
		}
		// Recompute labels; a reporting token cannot declare a universal sanction.
		report.Decision = gameroute.Decide(report.Pairs, report.Gameplay)
		next[i].Report = &report
		next[i].Received = now
		if e := atomicJSON(a.cfg.DataDir, "aria-game-tests.json", next); e != nil {
			apiError(w, 500, "report persistence failed")
			return
		}
		a.deviceJobs = next
		jsonReply(w, 200, map[string]any{"ok": true, "decision": report.Decision})
		return
	}
	apiError(w, 401, "invalid report token")
}
func gameAgentGuide(name string) string {
	return "آزمون مسیر بازی — " + name + " — نسخهٔ ۴.۸\n\n۱) بسته را روی همان رایانه‌ای باز کن که بازی روی آن اجرا می‌شود. VPN دیگر را پیش از آزمون خاموش کن.\n۲) sing-box نسخهٔ سازگار 1.14 را از منبع رسمی https://github.com/SagerNet/sing-box/releases بگیر. فایل اجرایی مناسب سیستم را کنار برنامه با نام sing-box یا sing-box.exe قرار بده.\n۳) روی Windows فایل start.cmd را با Run as administrator اجرا کن. روی Linux/macOS: chmod +x start.sh سپس sudo ./start.sh. TUN به مجوز سیستم نیاز دارد.\n۴) نشانی محلی نمایش‌داده‌شده را در مرورگر همین رایانه باز کن. آزمون سرویس روی دو مسیر مستقل اجرا می‌شود؛ انتخاب خودکار سرویس اختیاری است و سلامت ورود/مسابقه را ثابت نمی‌کند. HTTP 401، 429 یا خطای سرور نتیجهٔ نامشخص می‌دهد.\n۵) پس از انتخاب اولیه، مسیر خودکار قفل می‌شود تا وسط مسابقه IP عوض نشود. برای آزمون مجدد پیش از بازی، دکمهٔ آزمون و انتخاب دوباره را بزن.\n۶) بازی را کاملاً ببند، در صفحهٔ محلی مسیر مستقیم یا پروکسی را انتخاب کن و بازی را دوباره باز کن؛ ورود و یک مسابقه را واقعاً امتحان کن و نتیجه را ثبت کن. این تأیید از طرف کاربر است و در پنل با همین عنوان نمایش داده می‌شود.\n۷) نتیجه در پنل → بازی‌ها و مسیر سریع → آزمون از دستگاه دیده می‌شود. قطعی گزارش مانع کار تونل نیست؛ گزارش فقط شامل پاسخ‌های آزمون و نتیجهٔ واردشده است، نه رمز ادمین یا تاریخچهٔ بازی.\n\nفایل aria-game-test.json خصوصی است؛ لینک اتصال و توکن محدود گزارش دارد. توکن ۲۴ ساعت اعتبار دارد؛ سپس بستهٔ تازه بگیر. روی شبکهٔ تازه دوباره آزمون کن. برنامه APK یا کلاینت iOS نیست. نتیجهٔ ناشر به معنی تحریم قطعی نیست. در تونل کامل انتخاب مسیر برای همهٔ ترافیک عمومی است؛ برای جداسازی روی PC نام واقعی exe را با حالت فقط برنامه وارد کن.\n"
}
