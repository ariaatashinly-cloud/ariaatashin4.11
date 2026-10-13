package cdnscan

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// Official Cloudflare IPv4 ranges checked 2026-10-12 against /ips-v4.
const Ranges = "173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22"

func Allowed(raw string) bool {
	ip, e := netip.ParseAddr(raw)
	if e != nil || !ip.Is4() {
		return false
	}
	for _, s := range strings.Fields(Ranges) {
		p := netip.MustParsePrefix(s)
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

type Job struct {
	Host      string   `json:"host"`
	SNI       string   `json:"sni"`
	Port      int      `json:"port"`
	Identity  string   `json:"identity"`
	IPs       []string `json:"ips"`
	Repeats   int      `json:"repeats"`
	TimeoutMS int      `json:"timeoutMS"`
	Workers   int      `json:"workers"`
}
type Result struct {
	IP        string  `json:"ip"`
	Port      int     `json:"port"`
	OK        bool    `json:"ok"`
	MedianMS  int64   `json:"medianMS"`
	Loss      float64 `json:"lossPercent"`
	Successes int     `json:"successes"`
	Attempts  int     `json:"attempts"`
	Stage     string  `json:"stage"`
	Error     string  `json:"error,omitempty"`
	Tunnel    bool    `json:"tunnelVerified"`
	TunnelMS  int64   `json:"tunnelMS,omitempty"`
}
type Report struct {
	Version int      `json:"version"`
	Scope   string   `json:"scope"`
	At      int64    `json:"at"`
	Job     Job      `json:"job"`
	Results []Result `json:"results"`
	Note    string   `json:"note"`
}

func Candidates(input string, count int) ([]string, error) {
	if count < 1 || count > 128 {
		return nil, fmt.Errorf("count must be 1..128")
	}
	seen := map[string]bool{}
	out := []string{}
	add := func(s string) error {
		if !Allowed(s) {
			return fmt.Errorf("only official Cloudflare IPv4 ranges are accepted: %s", s)
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
		return nil
	}
	for _, s := range strings.FieldsFunc(input, func(r rune) bool { return r == '\n' || r == '\r' || r == ',' || r == ' ' || r == '\t' }) {
		if strings.Contains(s, "/") {
			p, e := netip.ParsePrefix(s)
			if e != nil || !p.Addr().Is4() || p.Bits() < 20 {
				return nil, fmt.Errorf("CIDR must be IPv4 /20..32")
			}
			if !Allowed(p.Masked().Addr().String()) {
				return nil, fmt.Errorf("CIDR outside Cloudflare")
			}
			for ip, n := p.Masked().Addr(), 0; p.Contains(ip) && n < count; ip, n = ip.Next(), n+1 {
				if e = add(ip.String()); e != nil {
					return nil, e
				}
				if len(out) >= count {
					return out, nil
				}
			}
		} else {
			if e := add(s); e != nil {
				return nil, e
			}
			if len(out) >= count {
				return out, nil
			}
		}
	}
	if len(out) > 0 {
		return out, nil
	}
	prefixes := strings.Fields(Ranges)
	for len(out) < count {
		b := make([]byte, 8)
		if _, e := rand.Read(b); e != nil {
			return nil, e
		}
		p := netip.MustParsePrefix(prefixes[int(binary.BigEndian.Uint32(b[:4]))%len(prefixes)])
		v := p.Addr().As4()
		base := binary.BigEndian.Uint32(v[:])
		span := uint32(1) << (32 - p.Bits())
		n := base + binary.BigEndian.Uint32(b[4:])%span
		var a [4]byte
		binary.BigEndian.PutUint32(a[:], n)
		add(netip.AddrFrom4(a).String())
	}
	return out, nil
}
func ValidJob(j Job) error {
	if len(j.IPs) < 1 || len(j.IPs) > 128 || j.Repeats < 1 || j.Repeats > 5 || j.Workers < 1 || j.Workers > 8 || j.TimeoutMS < 500 || j.TimeoutMS > 8000 {
		return fmt.Errorf("scan limits invalid")
	}
	if j.Identity == "" || len(j.Identity) > 128 {
		return fmt.Errorf("panel identity missing")
	}
	for _, h := range []string{j.Host, j.SNI} {
		if h == "" || net.ParseIP(h) != nil || strings.ContainsAny(h, "/:\\@?# \r\n\t") || !strings.Contains(h, ".") {
			return fmt.Errorf("valid Host and SNI required")
		}
	}
	switch j.Port {
	case 443, 2053, 2083, 2087, 2096, 8443:
	default:
		return fmt.Errorf("supported HTTPS CDN port required")
	}
	for _, ip := range j.IPs {
		if !Allowed(ip) {
			return fmt.Errorf("IP outside Cloudflare ranges")
		}
	}
	return nil
}
func Probe(ctx context.Context, j Job, ip string) Result {
	result := Result{IP: ip, Port: j.Port, Attempts: j.Repeats, Stage: "tls-and-origin"}
	times := []int64{}
	for i := 0; i < j.Repeats; i++ {
		start := time.Now()
		tr := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{ServerName: j.SNI, MinVersion: tls.VersionTLS12}, DialContext: func(c context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: time.Duration(j.TimeoutMS) * time.Millisecond}).DialContext(c, network, net.JoinHostPort(ip, fmt.Sprint(j.Port)))
		}, TLSHandshakeTimeout: time.Duration(j.TimeoutMS) * time.Millisecond, DisableKeepAlives: true, ForceAttemptHTTP2: false}
		client := &http.Client{Transport: tr, Timeout: time.Duration(j.TimeoutMS) * time.Millisecond, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		req, _ := http.NewRequestWithContext(ctx, "GET", "https://"+net.JoinHostPort(j.SNI, fmt.Sprint(j.Port))+"/live", nil)
		req.Host = j.Host
		resp, e := client.Do(req)
		if e == nil {
			var body struct {
				Alive    bool   `json:"alive"`
				Identity string `json:"identity"`
			}
			e = json.NewDecoder(io.LimitReader(resp.Body, 8192)).Decode(&body)
			resp.Body.Close()
			if e == nil && (resp.StatusCode != 200 || !body.Alive || body.Identity != j.Identity) {
				e = fmt.Errorf("origin identity mismatch")
			}
		}
		tr.CloseIdleConnections()
		if e == nil {
			result.Successes++
			times = append(times, time.Since(start).Milliseconds())
		} else {
			result.Error = "TLS، پاسخ مبدأ یا مهلت اتصال ناموفق بود"
		}
		if ctx.Err() != nil {
			break
		}
	}
	result.Loss = 100 * float64(j.Repeats-result.Successes) / float64(j.Repeats)
	result.OK = result.Successes == j.Repeats
	if len(times) > 0 {
		sort.Slice(times, func(i, k int) bool { return times[i] < times[k] })
		result.MedianMS = times[len(times)/2]
	}
	if result.OK {
		result.Error = ""
	}
	return result
}
func Scan(ctx context.Context, j Job, scope string, onResult func(Result)) Report {
	r := Report{Version: 1, Scope: scope, At: time.Now().Unix(), Job: j, Results: []Result{}, Note: "آزمون HTTPS با SNI و گواهی معتبر و هویت همین پنل است؛ بدون tunnelVerified، اتصال واقعی پروکسی یا اینترنت اپراتور تأیید نشده است."}
	if e := ValidJob(j); e != nil {
		r.Note = e.Error()
		return r
	}
	jobs := make(chan string)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for i := 0; i < j.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				v := Probe(ctx, j, ip)
				mu.Lock()
				r.Results = append(r.Results, v)
				mu.Unlock()
				if onResult != nil {
					onResult(v)
				}
			}
		}()
	}
sendLoop:
	for _, ip := range j.IPs {
		select {
		case jobs <- ip:
		case <-ctx.Done():
			break sendLoop
		}
	}
	close(jobs)
	wg.Wait()
	sort.Slice(r.Results, func(i, k int) bool {
		a, b := r.Results[i], r.Results[k]
		if a.OK != b.OK {
			return a.OK
		}
		if a.Successes != b.Successes {
			return a.Successes > b.Successes
		}
		return a.MedianMS < b.MedianMS
	})
	return r
}
