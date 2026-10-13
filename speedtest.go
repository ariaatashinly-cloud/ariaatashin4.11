package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sync"
	"time"
)

type SpeedResult struct {
	Download float64  `json:"downloadMbps"`
	Upload   float64  `json:"uploadMbps"`
	Ping     float64  `json:"pingMS"`
	Jitter   float64  `json:"jitterMS"`
	Loss     *float64 `json:"packetLoss,omitempty"`
	Server   string   `json:"server"`
	Country  string   `json:"country"`
	URL      string   `json:"url,omitempty"`
	Finished int64    `json:"finished"`
}
type SpeedState struct {
	Running bool         `json:"running"`
	Started int64        `json:"started"`
	Result  *SpeedResult `json:"result,omitempty"`
	Error   string       `json:"error,omitempty"`
}
type speedBuffer struct {
	mu sync.Mutex
	bytes.Buffer
}

func (b *speedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	if left := (256 << 10) - b.Len(); left > 0 {
		if len(p) > left {
			p = p[:left]
		}
		b.Buffer.Write(p)
	}
	return n, nil
}
func ooklaBinary() string {
	for _, path := range []string{os.Getenv("ARIA_SPEEDTEST_BIN"), "/usr/local/bin/ookla-speedtest", "/app/ookla-speedtest", "speedtest"} {
		if path == "" {
			continue
		}
		if p, e := exec.LookPath(path); e == nil {
			return p
		}
	}
	return ""
}
func parseSpeedResult(b []byte) (*SpeedResult, error) {
	var r struct {
		Type             string                            `json:"type"`
		Ping             struct{ Latency, Jitter float64 } `json:"ping"`
		Download, Upload struct{ Bandwidth int64 }
		PacketLoss       *float64 `json:"packetLoss"`
		Server           struct{ Name, Location, Country string }
		Result           struct{ URL string }
	}
	if json.Unmarshal(b, &r) != nil || r.Type != "result" || r.Download.Bandwidth < 0 || r.Upload.Bandwidth < 0 || r.Ping.Latency < 0 {
		return nil, fmt.Errorf("invalid Ookla result")
	}
	link := ""
	if u, e := url.Parse(r.Result.URL); e == nil && u.Scheme == "https" && u.Host == "www.speedtest.net" {
		link = u.String()
	}
	return &SpeedResult{Download: float64(r.Download.Bandwidth) * 8 / 1e6, Upload: float64(r.Upload.Bandwidth) * 8 / 1e6, Ping: r.Ping.Latency, Jitter: r.Ping.Jitter, Loss: r.PacketLoss, Server: r.Server.Name + " · " + r.Server.Location, Country: r.Server.Country, URL: link, Finished: time.Now().Unix()}, nil
}
func (a *App) speedAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" && r.URL.Path == "/api/speedtest" {
		a.speedMu.Lock()
		s := a.speed
		a.speedMu.Unlock()
		jsonReply(w, 200, map[string]any{"available": ooklaBinary() != "", "state": s, "scope": "panel-server", "provider": "Ookla", "note": "این تست روی سرور پنل اجرا می‌شود؛ سرعت گوشی یا پینگ بازی نیست. اجرای آزمون حجم مصرف می‌کند و به مجوز مناسب Ookla نیاز دارد."})
		return
	}
	if r.Method != "POST" || r.URL.Path != "/api/speedtest/run" {
		apiError(w, 405, "عملیات نامعتبر است")
		return
	}
	var in struct {
		Accepted bool `json:"acceptedTerms"`
	}
	if readBody(w, r, &in, 1024) != nil || !in.Accepted {
		apiError(w, 400, "شرایط Ookla و مجوز مناسب استفاده از آن را تأیید کن")
		return
	}
	bin := ooklaBinary()
	if bin == "" {
		apiError(w, 409, "ابزار رسمی Ookla روی سرور نصب نیست؛ آموزش نصب در همین بخش است")
		return
	}
	a.speedMu.Lock()
	if a.speed.Running {
		a.speedMu.Unlock()
		apiError(w, 409, "یک آزمون در حال اجرا است")
		return
	}
	if time.Now().Unix()-a.speed.Started < 60 {
		a.speedMu.Unlock()
		apiError(w, 429, "بین دو آزمون دست‌کم یک دقیقه فاصله بده")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	a.speedCancel = cancel
	a.speed = SpeedState{Running: true, Started: time.Now().Unix()}
	a.speedMu.Unlock()
	go func() {
		defer cancel()
		var output speedBuffer
		cmd := exec.CommandContext(ctx, bin, "--format=json", "--progress=no", "--accept-license", "--accept-gdpr")
		cmd.Stdout = &output
		cmd.Stderr = &output
		err := cmd.Run()
		var result *SpeedResult
		if err == nil {
			result, err = parseSpeedResult(output.Bytes())
		}
		a.speedMu.Lock()
		defer a.speedMu.Unlock()
		a.speed.Running = false
		a.speedCancel = nil
		if err != nil {
			a.speed.Error = "آزمون Ookla کامل نشد؛ دسترسی سرور به شبکهٔ آزمون، نصب نسخهٔ رسمی و محدودیت میزبان را بررسی کن."
		} else {
			a.speed.Result = result
		}
	}()
	jsonReply(w, 202, map[string]bool{"started": true})
}
func (a *App) stopSpeedTest() {
	a.speedMu.Lock()
	defer a.speedMu.Unlock()
	if a.speedCancel != nil {
		a.speedCancel()
	}
}
