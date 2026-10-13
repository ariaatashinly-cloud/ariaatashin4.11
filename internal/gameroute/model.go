// Package gameroute contains the device-side route test contract. HTTP service
// reachability is evidence about a path, never proof of a game's matchmaking.
package gameroute

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"time"
)

const Version = "4.8.0"

type Target struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}
type Job struct {
	Version     int            `json:"version"`
	ID          string         `json:"id"`
	GameID      string         `json:"gameID"`
	GameName    string         `json:"gameName"`
	Mode        string         `json:"mode"`
	Expires     int64          `json:"expires"`
	ReportURL   string         `json:"reportURL"`
	ReportToken string         `json:"reportToken"`
	Targets     []Target       `json:"targets"`
	AutoService bool           `json:"autoService"`
	Config      map[string]any `json:"config"`
}
type Sample struct {
	Status int    `json:"status"`
	MS     int64  `json:"ms"`
	Error  string `json:"error,omitempty"`
}
type Pair struct {
	Target string   `json:"target"`
	Direct []Sample `json:"direct"`
	Proxy  []Sample `json:"proxy"`
}
type Gameplay struct {
	Direct string `json:"direct"`
	Proxy  string `json:"proxy"`
}
type Decision struct {
	State     string `json:"state"`
	Suggested string `json:"suggested"`
	Scope     string `json:"scope"`
	DirectMS  int64  `json:"directMS"`
	ProxyMS   int64  `json:"proxyMS"`
}
type Report struct {
	JobID        string   `json:"jobID"`
	GameID       string   `json:"gameID"`
	Sequence     int64    `json:"sequence"`
	Completed    int64    `json:"completed"`
	AgentVersion string   `json:"agentVersion"`
	Pairs        []Pair   `json:"pairs"`
	Gameplay     Gameplay `json:"gameplay"`
	Decision     Decision `json:"decision"`
	Selected     string   `json:"selected"`
	Locked       bool     `json:"locked"`
	Applied      bool     `json:"applied"`
}

// Failed requests are distinguished from inconclusive server responses. An
// authentication challenge, rate limit or server outage must not become a ban.
func sampleState(s Sample) string {
	if s.Error == "redirect" {
		return "unknown"
	}
	if s.Error != "" {
		return "failed"
	}
	if s.Status >= 200 && s.Status < 300 {
		return "healthy"
	}
	if s.Status == 403 || s.Status == 451 {
		return "failed"
	}
	return "unknown"
}
func pathState(pairs []Pair, direct bool) (string, int64) {
	healthy, failed, total := 0, 0, 0
	latencies := []int64{}
	for _, p := range pairs {
		ss := p.Proxy
		if direct {
			ss = p.Direct
		}
		for _, s := range ss {
			total++
			switch sampleState(s) {
			case "healthy":
				healthy++
				latencies = append(latencies, s.MS)
			case "failed":
				failed++
			}
		}
	}
	median := int64(0)
	if len(latencies) > 0 {
		sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
		median = latencies[len(latencies)/2]
	}
	if total < 2 {
		return "unknown", median
	}
	if healthy == total {
		return "healthy", median
	}
	if failed == total {
		return "failed", median
	}
	return "unknown", median
}
func Decide(pairs []Pair, g Gameplay) Decision {
	d, dm := pathState(pairs, true)
	p, pm := pathState(pairs, false)
	v := Decision{State: "inconclusive", Suggested: "keep", Scope: "service", DirectMS: dm, ProxyMS: pm}
	if g.Direct == "passed" {
		v.State = "gameplay-direct"
		v.Suggested = "direct"
		v.Scope = "user-gameplay"
		return v
	}
	if g.Proxy == "passed" {
		v.State = "gameplay-proxy"
		v.Suggested = "proxy"
		v.Scope = "user-gameplay"
		return v
	}
	if g.Direct == "failed" && g.Proxy == "failed" {
		v.State = "gameplay-unavailable"
		v.Scope = "user-gameplay"
		return v
	}
	if d == "healthy" && g.Direct != "failed" {
		v.State = "direct-service"
		v.Suggested = "direct"
		if p == "healthy" {
			v.State = "both-services"
			if pm+80 < dm {
				v.Suggested = "proxy"
			}
		}
	} else if (d == "failed" || g.Direct == "failed") && p == "healthy" && g.Proxy != "failed" {
		v.State = "proxy-service"
		v.Suggested = "proxy"
	} else if d == "failed" && p == "failed" {
		v.State = "services-unavailable"
	}
	return v
}
func ValidateReport(r Report, targets []Target) error {
	if r.Sequence < 1 || r.Sequence > 9007199254740991 || r.AgentVersion != Version || len(r.Pairs) != len(targets) || len(targets) < 1 || len(targets) > 4 {
		return fmt.Errorf("invalid report")
	}
	for _, v := range []string{r.Gameplay.Direct, r.Gameplay.Proxy} {
		if v != "untried" && v != "passed" && v != "failed" {
			return fmt.Errorf("invalid gameplay result")
		}
	}
	if r.Selected != "direct" && r.Selected != "proxy" {
		return fmt.Errorf("invalid selection")
	}
	for i, p := range r.Pairs {
		if p.Target != targets[i].URL || len(p.Direct) != 2 || len(p.Proxy) != 2 {
			return fmt.Errorf("unexpected target or samples")
		}
		for _, ss := range [][]Sample{p.Direct, p.Proxy} {
			for _, s := range ss {
				if s.MS < 0 || s.MS > 30000 || (s.Status != 0 && (s.Status < 100 || s.Status > 599)) {
					return fmt.Errorf("invalid sample")
				}
				switch s.Error {
				case "", "timeout", "tls", "network", "redirect":
				default:
					return fmt.Errorf("invalid error")
				}
				if s.Status == 0 && s.Error == "" {
					return fmt.Errorf("empty result")
				}
			}
		}
	}
	return nil
}
func ValidateJob(j Job) error {
	if j.Version != 1 || j.ID == "" || j.Config == nil || len(j.Targets) == 0 || len(j.Targets) > 4 || j.Expires < time.Now().Unix() {
		return fmt.Errorf("job is invalid or expired; download a new kit")
	}
	for _, t := range j.Targets {
		u, e := url.Parse(t.URL)
		if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("only public HTTPS service targets without credentials are allowed")
		}
	}
	u, e := url.Parse(j.ReportURL)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(j.ReportToken) < 32 {
		return fmt.Errorf("HTTPS reporting endpoint required")
	}
	return nil
}
func CloneConfig(c map[string]any) map[string]any {
	b, _ := json.Marshal(c)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

// The test listeners are forced to DIFFERENT outbounds before all game/LAN
// rules. The proxy test never follows game-smart, so selecting direct cannot
// silently turn both tests into direct tests.
func DeviceConfig(base map[string]any, tun bool, directPort, proxyPort, controllerPort int, secret string, selected string) map[string]any {
	c := CloneConfig(base)
	route := c["route"].(map[string]any)
	// The initial probe has no TUN and needs no privileged interface monitor.
	if !tun {
		delete(route, "auto_detect_interface")
	}
	if route["final"] == "game-route" {
		route["final"] = "game-smart"
	}
	rules := route["rules"].([]any)
	for _, r := range rules {
		m := r.(map[string]any)
		if m["outbound"] == "game-route" {
			m["outbound"] = "game-smart"
		}
	}
	forced := []any{
		map[string]any{"inbound": []string{"test-direct"}, "action": "resolve", "server": "bootstrap", "disable_cache": true},
		map[string]any{"inbound": []string{"test-direct"}, "action": "route", "outbound": "direct"},
		map[string]any{"inbound": []string{"test-proxy"}, "action": "resolve", "server": "probe-proxy-dns", "disable_cache": true},
		map[string]any{"inbound": []string{"test-proxy"}, "action": "route", "outbound": "game-route"},
	}
	route["rules"] = append(forced, rules...)
	outs := c["outbounds"].([]any)
	chosen := "game-route"
	if selected == "direct" {
		chosen = "direct"
	}
	c["outbounds"] = append(outs, map[string]any{"type": "selector", "tag": "game-smart", "outbounds": []string{"direct", "game-route"}, "default": chosen, "interrupt_exist_connections": false})
	dns := c["dns"].(map[string]any)
	dns["servers"] = append(dns["servers"].([]any), map[string]any{"type": "https", "tag": "probe-proxy-dns", "server": "cloudflare-dns.com", "server_port": 443, "path": "/dns-query", "tls": map[string]any{"enabled": true, "server_name": "cloudflare-dns.com"}, "domain_resolver": "bootstrap", "detour": "game-route"})
	// Game DNS follows its actual selected exit. Direct targets retain the OS
	// bootstrap resolver; proxy destination names are resolved through the exit.
	for _, s := range dns["servers"].([]any) {
		m := s.(map[string]any)
		if m["tag"] == "personal" {
			m["detour"] = "game-smart"
		}
	}
	in := []any{}
	if tun {
		in = c["inbounds"].([]any)
	}
	for i, p := range []int{directPort, proxyPort} {
		tag := "test-direct"
		if i == 1 {
			tag = "test-proxy"
		}
		in = append(in, map[string]any{"type": "mixed", "tag": tag, "listen": "127.0.0.1", "listen_port": p, "users": []any{map[string]string{"username": "aria", "password": secret}}, "set_system_proxy": false})
	}
	c["inbounds"] = in
	c["experimental"] = map[string]any{"clash_api": map[string]any{"external_controller": fmt.Sprintf("127.0.0.1:%d", controllerPort), "secret": secret, "access_control_allow_origin": []string{"http://127.0.0.1"}, "access_control_allow_private_network": false}}
	return c
}
