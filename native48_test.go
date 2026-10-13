//go:build integration

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"launcher/internal/gameroute"
)

func port48(t *testing.T) int {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return p
}
func startDeviceCore48(t *testing.T, ctx context.Context, bin string, c map[string]any, dir string) func() {
	b, _ := json.Marshal(c)
	file := filepath.Join(dir, "device.json")
	os.WriteFile(file, b, 0600)
	if out, e := exec.CommandContext(ctx, bin, "check", "-c", file).CombinedOutput(); e != nil {
		t.Fatal("native device schema", e, string(out))
	}
	logfile, e := os.OpenFile(filepath.Join(dir, "device.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.CommandContext(ctx, bin, "run", "-c", file)
	cmd.Stdout = logfile
	cmd.Stderr = logfile
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	stop := func() { cmd.Process.Kill(); cmd.Wait(); logfile.Close() }
	addr := c["experimental"].(map[string]any)["clash_api"].(map[string]any)["external_controller"].(string)
	for i := 0; i < 80; i++ {
		conn, e := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if e == nil {
			conn.Close()
			return stop
		}
		time.Sleep(50 * time.Millisecond)
	}
	stop()
	out, _ := os.ReadFile(filepath.Join(dir, "device.log"))
	t.Fatal("device core did not start", string(out))
	return nil
}
func TestNative48IndependentPathsAndRealClashSelection(t *testing.T) {
	bin := os.Getenv("ARIA_TEST_SING_BOX_CLASH")
	if bin == "" {
		bin = os.Getenv("ARIA_TEST_SING_BOX")
	}
	if bin == "" {
		t.Skip("set ARIA_TEST_SING_BOX")
	}
	a, ctx := nativeTestApp(t)
	allowNativeTestLoopback(t, ctx, a.service)
	cert, root := relayCertificate45(t)
	origin := httptest.NewUnstartedServer(a)
	origin.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	origin.StartTLS()
	defer origin.Close()
	a.mu.Lock()
	a.state.Settings.PublicURL = origin.URL
	a.mu.Unlock()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/users", strings.NewReader(`{"name":"Device48","count":1,"quotaGB":1,"days":1,"profiles":["vless-ws"]}`)).WithContext(ctx)
	r.Header.Set("Content-Type", "application/json")
	a.createUsers(w, r, a.service)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	u := a.snapshot().Users[0]
	c := DNSClient{ID: "dns-device", Key: strings.Repeat("b", 48), Name: "DNS", Enabled: true, Presets: []string{"rainbow-six"}}
	a.dns.data.Clients = []DNSClient{c}
	a.dns.data.Settings.Enabled = true
	data, status, e := a.gamingExportData(httptest.NewRequest("GET", fmt.Sprintf("/api/gaming/export?email=%s&profile=vless-ws&dns=%s&mode=full&platform=windows&dnsMode=exit&game=rainbow-six&deviceTest=1", u.Email, c.ID), nil))
	if e != nil {
		t.Fatal(status, e)
	}
	base := data["config"].(map[string]any)
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root}), 0600)
	for _, o := range base["outbounds"].([]any) {
		v := o.(map[string]any)
		if tls, ok := v["tls"].(map[string]any); ok {
			tls["certificate_path"] = ca
		}
	}
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	target.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	target.StartTLS()
	defer target.Close()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root}))
	for _, broken := range []bool{false, true} {
		t.Run(fmt.Sprint("proxy-broken-", broken), func(t *testing.T) {
			cfg := gameroute.CloneConfig(base)
			if broken {
				cfg["outbounds"].([]any)[0].(map[string]any)["server_port"] = 1
			}
			dp, pp, cp := port48(t), port48(t), port48(t)
			secret := strings.Repeat("a", 64)
			device := gameroute.DeviceConfig(cfg, false, dp, pp, cp, secret, "direct")
			stop := startDeviceCore48(t, ctx, bin, device, t.TempDir())
			defer stop()
			direct, proxy := gameroute.LocalClient(dp, secret), gameroute.LocalClient(pp, secret)
			for _, client := range []*http.Client{direct, proxy} {
				client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: pool}
			}
			pairs := gameroute.Probe(ctx, []gameroute.Target{{URL: target.URL}}, direct, proxy)
			if pairs[0].Direct[0].Status != 204 {
				t.Fatal("direct path failed", pairs)
			}
			if !broken && pairs[0].Proxy[0].Status != 204 {
				t.Fatal("real VLESS path failed", pairs)
			}
			if broken && pairs[0].Proxy[0].Error == "" {
				t.Fatal("proxy test silently followed the direct selector", pairs)
			}
			controller := fmt.Sprintf("http://127.0.0.1:%d", cp)
			for _, selection := range []string{"game-route", "direct"} {
				req, _ := http.NewRequestWithContext(ctx, "PUT", controller+"/proxies/game-smart", bytes.NewBufferString(`{"name":"`+selection+`"}`))
				req.Header.Set("Authorization", "Bearer "+secret)
				req.Header.Set("Content-Type", "application/json")
				client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: time.Second}
				res, e := client.Do(req)
				if e != nil || res.StatusCode != 204 {
					t.Fatal("real selector failed", e)
				}
				res.Body.Close()
				req, _ = http.NewRequestWithContext(ctx, "GET", controller+"/proxies/game-smart", nil)
				req.Header.Set("Authorization", "Bearer "+secret)
				res, e = client.Do(req)
				if e != nil {
					t.Fatal(e)
				}
				b, _ := io.ReadAll(res.Body)
				res.Body.Close()
				var actual struct {
					Now string `json:"now"`
				}
				if json.Unmarshal(b, &actual) != nil || actual.Now != selection {
					t.Fatal("selection not applied", string(b))
				}
			}
			if !broken {
				job := gameroute.Job{Version: 1, ID: "gt-native48", GameID: "rainbow-six", GameName: "Device fixture", Mode: "full", Expires: time.Now().Add(time.Hour).Unix(), ReportURL: origin.URL + "/api/gaming/client-report", ReportToken: strings.Repeat("c", 64), Targets: []gameroute.Target{{URL: target.URL}}, AutoService: true, Config: cfg}
				a.deviceMu.Lock()
				a.deviceJobs = append(a.deviceJobs, GameDeviceJob{ID: job.ID, GameID: job.GameID, Email: u.Email, DNSID: c.ID, Created: time.Now().Unix(), Expires: job.Expires, TokenHash: gameTokenHash(job.ReportToken), Targets: job.Targets, AutoService: true})
				a.deviceMu.Unlock()
				work := t.TempDir()
				jobFile := filepath.Join(work, "job.json")
				b, _ := json.Marshal(job)
				os.WriteFile(jobFile, b, 0600)
				agentBin, _ := filepath.Abs("web/game-agent/game-route-agent-linux-amd64")
				os.Chmod(agentBin, 0700)
				cmd := exec.CommandContext(ctx, agentBin, "--job", jobFile, "--sing-box", bin, "--once")
				cmd.Env = append(os.Environ(), "SSL_CERT_FILE="+ca)
				if out, e := cmd.CombinedOutput(); e != nil {
					t.Fatal("real companion CLI failed", e, string(out))
				}
				b, e = os.ReadFile(filepath.Join(work, "aria-game-result.json"))
				var result gameroute.Report
				if e != nil || json.Unmarshal(b, &result) != nil || result.Decision.State != "both-services" || result.Selected != "direct" || result.Applied {
					t.Fatal("real companion produced wrong probe-only result", e, string(b))
				}
				a.deviceMu.Lock()
				var received bool
				for _, j := range a.deviceJobs {
					if j.ID == job.ID && j.Report != nil && j.Report.Decision.State == "both-services" {
						received = true
					}
				}
				a.deviceMu.Unlock()
				if !received {
					t.Fatal("real companion report did not reach panel through the VLESS proxy")
				}
			}
		})
	}
	for _, mode := range []string{"full", "games", "apps"} {
		t.Run("tun-schema-"+mode, func(t *testing.T) {
			cfg := gameroute.CloneConfig(base)
			req := httptest.NewRequest("GET", "/api/gaming/export?mode="+mode+"&platform=windows&processes=RainbowSix.exe&dnsMode=exit", nil)
			if e := applyGamePolicy(cfg, DNSClient{Presets: []string{"rainbow-six"}}, req); e != nil {
				t.Fatal(e)
			}
			device := gameroute.DeviceConfig(cfg, true, 21081, 21082, 29081, strings.Repeat("b", 64), "proxy")
			b, _ := json.Marshal(device)
			p := filepath.Join(t.TempDir(), "tun.json")
			os.WriteFile(p, b, 0600)
			if out, e := exec.Command(bin, "check", "-c", p).CombinedOutput(); e != nil {
				t.Fatal("TUN config rejected", e, string(out))
			}
		})
	}
}
