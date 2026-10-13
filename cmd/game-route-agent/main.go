package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"launcher/internal/gameroute"
)

type agent struct {
	mu            sync.Mutex
	operation     sync.Mutex
	pushMu        sync.Mutex
	job           gameroute.Job
	report        gameroute.Report
	direct, proxy *http.Client
	controller    string
	secret        string
	localSecret   string
	busy          bool
	notice        string
	upload        string
	tun           bool
	ctx           context.Context
}

func token() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b)
}
func privateJSON(path string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	if e = f.Chmod(0600); e != nil {
		return e
	}
	_, e = f.Write(b)
	return e
}
func freePort() (int, error) {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		return 0, e
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}
func core(ctx context.Context, bin string, config map[string]any, dir string) (func(), error) {
	file := filepath.Join(dir, "runtime.json")
	if e := privateJSON(file, config); e != nil {
		return nil, e
	}
	logFile, e := os.OpenFile(filepath.Join(dir, "engine.log"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if e != nil {
		return nil, e
	}
	cmd := exec.CommandContext(ctx, bin, "run", "-c", file)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if e = cmd.Start(); e != nil {
		logFile.Close()
		return nil, fmt.Errorf("cannot start sing-box; place the compatible executable beside the agent")
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait(); logFile.Close() }()
	stop := func() {
		_ = cmd.Process.Signal(os.Interrupt)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	}
	controller := config["experimental"].(map[string]any)["clash_api"].(map[string]any)
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}}
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case e := <-done:
			return nil, fmt.Errorf("sing-box exited (%v); verify sing-box 1.14 with Clash API and TUN permission", e)
		case <-deadline.C:
			stop()
			return nil, errors.New("sing-box local controller did not start")
		case <-ctx.Done():
			stop()
			return nil, ctx.Err()
		case <-ticker.C:
			r, _ := http.NewRequestWithContext(ctx, "GET", "http://"+controller["external_controller"].(string)+"/version", nil)
			r.Header.Set("Authorization", "Bearer "+controller["secret"].(string))
			resp, e := client.Do(r)
			if e == nil {
				resp.Body.Close()
				if resp.StatusCode == 200 {
					return stop, nil
				}
			}
		}
	}
}
func (a *agent) selectRoute(route string) error {
	name := "game-route"
	if route == "direct" {
		name = "direct"
	}
	body, _ := json.Marshal(map[string]string{"name": name})
	r, _ := http.NewRequestWithContext(a.ctx, "PUT", a.controller+"/proxies/game-smart", bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+a.secret)
	r.Header.Set("Content-Type", "application/json")
	c := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}}
	resp, e := c.Do(r)
	if e != nil {
		return errors.New("local selector unavailable")
	}
	resp.Body.Close()
	if resp.StatusCode != 204 && resp.StatusCode != 200 {
		return errors.New("local selector rejected route")
	}
	get, _ := http.NewRequestWithContext(a.ctx, "GET", a.controller+"/proxies/game-smart", nil)
	get.Header.Set("Authorization", "Bearer "+a.secret)
	resp, e = c.Do(get)
	if e != nil {
		return errors.New("cannot verify selected route")
	}
	defer resp.Body.Close()
	var current struct {
		Now string `json:"now"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 8192)).Decode(&current) != nil || current.Now != name {
		return errors.New("selector did not apply route")
	}
	return nil
}
func (a *agent) checkApplied() {
	// A dead core or externally changed selector must not be reported as an
	// applied game tunnel. Read the controller; do not change a playing route.
	if a.tun {
		a.mu.Lock()
		selected := a.report.Selected
		a.mu.Unlock()
		expected := "game-route"
		if selected == "direct" {
			expected = "direct"
		}
		get, _ := http.NewRequestWithContext(a.ctx, "GET", a.controller+"/proxies/game-smart", nil)
		get.Header.Set("Authorization", "Bearer "+a.secret)
		client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}}
		resp, e := client.Do(get)
		alive := false
		if e == nil {
			var current struct {
				Now string `json:"now"`
			}
			alive = resp.StatusCode == 200 && json.NewDecoder(io.LimitReader(resp.Body, 8192)).Decode(&current) == nil && current.Now == expected
			resp.Body.Close()
		}
		a.mu.Lock()
		a.report.Applied = alive
		if !alive {
			a.notice = "هسته یا مسیر انتخاب‌شده در دسترس نیست؛ نتیجهٔ اعمال تونل تأیید نمی‌شود."
		}
		a.mu.Unlock()
	}
}
func (a *agent) push() {
	a.pushMu.Lock()
	defer a.pushMu.Unlock()
	a.checkApplied()
	a.mu.Lock()
	next := time.Now().UnixMilli()
	if next <= a.report.Sequence {
		next = a.report.Sequence + 1
	}
	a.report.Sequence = next
	a.report.Completed = time.Now().UnixMilli()
	copy := a.report
	a.mu.Unlock()
	b, _ := json.Marshal(copy)
	r, _ := http.NewRequestWithContext(a.ctx, "POST", a.job.ReportURL, bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+a.job.ReportToken)
	c := *a.proxy
	c.Timeout = 8 * time.Second
	c.CheckRedirect = func(r *http.Request, v []*http.Request) error { return http.ErrUseLastResponse }
	response, e := c.Do(r)
	message := "گزارش به پنل نرسید؛ نتیجهٔ محلی و تونل همچنان قابل استفاده‌اند."
	if e == nil {
		response.Body.Close()
		if response.StatusCode == 200 {
			message = "نتیجه در پنل ثبت شد."
		} else if response.StatusCode == 403 {
			message = "اعتبار گزارش تمام یا حساب غیرفعال شده؛ بستهٔ تازه بگیر."
		}
	}
	a.mu.Lock()
	a.upload = message
	a.mu.Unlock()
}
func (a *agent) test(selectAgain bool) {
	a.mu.Lock()
	if a.busy {
		a.mu.Unlock()
		return
	}
	a.busy = true
	a.notice = "در حال آزمون دو مسیر مستقل…"
	a.mu.Unlock()
	defer func() { a.mu.Lock(); a.busy = false; a.mu.Unlock() }()
	a.operation.Lock()
	defer a.operation.Unlock()
	ctx, cancel := context.WithTimeout(a.ctx, 32*time.Second)
	pairs := gameroute.Probe(ctx, a.job.Targets, a.direct, a.proxy)
	cancel()
	a.mu.Lock()
	a.report.Pairs = pairs
	a.report.Gameplay = gameroute.Gameplay{Direct: "untried", Proxy: "untried"}
	a.report.Decision = gameroute.Decide(pairs, a.report.Gameplay)
	route := a.report.Decision.Suggested
	apply := selectAgain && a.job.AutoService && route != "keep"
	a.mu.Unlock()
	if apply {
		e := a.selectRoute(route)
		a.mu.Lock()
		if e == nil {
			a.report.Selected = route
			a.report.Applied = a.tun
		} else {
			a.notice = e.Error()
		}
		a.mu.Unlock()
	}
	a.mu.Lock()
	a.report.Locked = true
	a.notice = "آزمون تمام شد؛ مسیر تا آزمون بعدی ثابت می‌ماند. ورود و مسابقه را جدا امتحان کن."
	a.mu.Unlock()
	a.push()
}
func (a *agent) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	host, _, e := net.SplitHostPort(r.Host)
	if e != nil || host != "127.0.0.1" {
		http.Error(w, "local host required", 403)
		return
	}
	if r.URL.Path == "/" && r.Method == "GET" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
		_, _ = io.WriteString(w, localHTML)
		return
	}
	if r.Header.Get("Origin") != "" && r.Header.Get("Origin") != "http://"+r.Host {
		http.Error(w, "origin rejected", 403)
		return
	}
	if subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")), []byte(a.localSecret)) != 1 {
		http.Error(w, "local authorization required", 401)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Path == "/status" && r.Method == "GET" {
		a.checkApplied()
		a.mu.Lock()
		defer a.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"report": a.report, "busy": a.busy, "notice": a.notice, "upload": a.upload, "game": a.job.GameName, "tun": a.tun, "autoService": a.job.AutoService})
		return
	}
	if r.URL.Path != "/action" || r.Method != "POST" {
		http.Error(w, "not found", 404)
		return
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		http.Error(w, "JSON required", 400)
		return
	}
	var in struct {
		Action string `json:"action"`
		Route  string `json:"route"`
		Result string `json:"result"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048)).Decode(&in) != nil {
		http.Error(w, "invalid JSON", 400)
		return
	}
	a.mu.Lock()
	if a.busy {
		a.mu.Unlock()
		http.Error(w, "test in progress", 409)
		return
	}
	a.mu.Unlock()
	if in.Action == "retest" {
		go a.test(true)
		_, _ = io.WriteString(w, `{"ok":true}`)
		return
	}
	a.operation.Lock()
	defer a.operation.Unlock()
	a.mu.Lock()
	busy := a.busy
	a.mu.Unlock()
	if busy {
		http.Error(w, "test in progress", 409)
		return
	}
	if in.Route != "direct" && in.Route != "proxy" {
		http.Error(w, "invalid route", 400)
		return
	}
	if in.Action == "select" {
		if e := a.selectRoute(in.Route); e != nil {
			http.Error(w, e.Error(), 502)
			return
		}
		a.mu.Lock()
		a.report.Selected = in.Route
		a.report.Locked = true
		a.report.Applied = a.tun
		a.report.Decision = gameroute.Decide(a.report.Pairs, a.report.Gameplay)
		a.notice = "مسیر انتخاب شد؛ بازی را کاملاً ببند و دوباره باز کن، سپس نتیجهٔ ورود و مسابقه را ثبت کن."
		a.mu.Unlock()
	} else if in.Action == "confirm" {
		a.mu.Lock()
		if !a.tun || a.report.Selected != in.Route || (in.Result != "passed" && in.Result != "failed") {
			a.mu.Unlock()
			http.Error(w, "test the selected active TUN route first", 409)
			return
		}
		if in.Route == "direct" {
			a.report.Gameplay.Direct = in.Result
		} else {
			a.report.Gameplay.Proxy = in.Result
		}
		a.report.Decision = gameroute.Decide(a.report.Pairs, a.report.Gameplay)
		a.mu.Unlock()
	} else {
		http.Error(w, "invalid action", 400)
		return
	}
	go a.push()
	_, _ = io.WriteString(w, `{"ok":true}`)
}
func run() error {
	jobFile := flag.String("job", "aria-game-test.json", "private test job from panel")
	engine := flag.String("sing-box", "sing-box", "sing-box 1.14 executable")
	tun := flag.Bool("tun", false, "start the game TUN after testing; requires OS permission")
	once := flag.Bool("once", false, "test only, write report and exit without starting TUN")
	flag.Parse()
	b, e := os.ReadFile(*jobFile)
	if e != nil {
		return e
	}
	var job gameroute.Job
	if json.Unmarshal(b, &job) != nil {
		return errors.New("job JSON invalid")
	}
	if e = gameroute.ValidateJob(job); e != nil {
		return e
	}
	bin := *engine
	if strings.ContainsAny(bin, "/\\") || strings.HasSuffix(bin, ".exe") {
		if abs, e := filepath.Abs(bin); e == nil {
			bin = abs
		}
	}
	if _, e = exec.LookPath(bin); e != nil {
		return errors.New("install compatible sing-box 1.14 beside the agent; see README-FA.txt")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	dir, e := os.MkdirTemp("", "aria-game-device-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(dir)
	dp, e := freePort()
	if e != nil {
		return e
	}
	pp, e := freePort()
	if e != nil {
		return e
	}
	cp, e := freePort()
	if e != nil {
		return e
	}
	secret := token()
	config := gameroute.DeviceConfig(job.Config, false, dp, pp, cp, secret, "proxy")
	stop, e := core(ctx, bin, config, dir)
	if e != nil {
		return e
	}
	a := &agent{job: job, secret: secret, localSecret: token(), ctx: ctx, direct: gameroute.LocalClient(dp, secret), proxy: gameroute.LocalClient(pp, secret), controller: fmt.Sprintf("http://127.0.0.1:%d", cp), report: gameroute.Report{JobID: job.ID, GameID: job.GameID, AgentVersion: gameroute.Version, Selected: "proxy", Gameplay: gameroute.Gameplay{Direct: "untried", Proxy: "untried"}, Locked: true}}
	fmt.Println("Testing direct and proxy service paths on this device; turn off other VPN clients.")
	a.test(true)
	if *once {
		defer stop()
		a.mu.Lock()
		defer a.mu.Unlock()
		return privateJSON(filepath.Join(filepath.Dir(*jobFile), "aria-game-result.json"), a.report)
	}
	stop()
	config = gameroute.DeviceConfig(job.Config, *tun, dp, pp, cp, secret, a.report.Selected)
	stop, e = core(ctx, bin, config, dir)
	if e != nil {
		return e
	}
	defer stop()
	a.tun = *tun
	a.report.Applied = *tun
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		return e
	}
	srv := &http.Server{Handler: http.HandlerFunc(a.serve), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	go func() { _ = srv.Serve(l) }()
	defer srv.Close()
	fmt.Printf("Open on this computer: http://%s/#%s\n", l.Addr(), a.localSecret)
	if !*tun {
		fmt.Println("Probe-only mode: no game traffic is routed; restart with --tun to apply a game route.")
	}
	go a.push()
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			go a.test(false)
		}
	}
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
