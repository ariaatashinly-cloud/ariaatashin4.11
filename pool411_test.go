package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPool411ContinuousDowntimeAndGaps(t *testing.T) {
	cfg := defaultPoolSettings()
	cfg.IntervalSeconds = 300
	now := int64(1700000000000)
	h := ServiceHealth{}
	for minute := 0; minute < 120; minute += 5 {
		h = advanceHealth(h, ProbeResult{State: "down"}, now+int64(minute)*60000, cfg)
		if healthTransferDue(h, now+int64(minute)*60000, cfg) {
			t.Fatal("momentary/early failure triggered move")
		}
	}
	h = advanceHealth(h, ProbeResult{State: "down"}, now+120*60000, cfg)
	if !healthTransferDue(h, now+120*60000, cfg) {
		t.Fatal("two hour sustained outage did not become due")
	}
	h = advanceHealth(h, ProbeResult{State: "ok"}, now+125*60000, cfg)
	if h.FailedSince != 0 || h.Failures != 0 {
		t.Fatal("success did not reset timer")
	}
	h = advanceHealth(h, ProbeResult{State: "down"}, now+130*60000, cfg)
	h = advanceHealth(h, ProbeResult{State: "unknown"}, now+135*60000, cfg)
	if h.FailedSince != 0 {
		t.Fatal("ambiguous probe counted as down")
	}
	h = advanceHealth(h, ProbeResult{State: "down"}, now+140*60000, cfg)
	h = advanceHealth(h, ProbeResult{State: "down"}, now+200*60000, cfg)
	if h.FailedSince != now+200*60000 {
		t.Fatal("sleeping monitor counted unobserved downtime")
	}
	h.LastTransfer = now + 200*60000
	h.FailedSince = now
	h.Failures = 30
	if healthTransferDue(h, now+205*60000, cfg) {
		t.Fatal("cooldown ignored")
	}
}

type poolRemote411 struct {
	mu              sync.Mutex
	users           map[string]SoldService
	inputs          map[string]ProvisionInput
	creates         int
	failAfterCreate bool
	offline         bool
	server          *httptest.Server
}

func newPoolRemote411(t *testing.T) *poolRemote411 {
	r := &poolRemote411{users: map[string]SoldService{}, inputs: map[string]ProvisionInput{}}
	r.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		defer r.mu.Unlock()
		if req.Header.Get("Authorization") != "Bearer fixture-token" {
			http.Error(w, "unauthorized", 401)
			return
		}
		if r.offline {
			http.Error(w, "offline", 503)
			return
		}
		if req.URL.Path == "/api/v1/pool-status" {
			var n int64
			for _, v := range r.users {
				n += v.Used
			}
			jsonReply(w, 200, map[string]any{"ready": true, "traffic": n})
			return
		}
		if req.URL.Path == "/api/v1/clients" && req.Method == "POST" {
			var p ProvisionInput
			_ = json.NewDecoder(req.Body).Decode(&p)
			if !validProvision(p) {
				http.Error(w, "bad provision", 400)
				return
			}
			if v, ok := r.users[p.Email]; ok {
				if r.inputs[p.Email].OperationID != p.OperationID {
					http.Error(w, "mismatch", 409)
					return
				}
				jsonReply(w, 200, v)
				return
			}
			r.creates++
			r.inputs[p.Email] = p
			v := SoldService{Email: p.Email, Name: p.Name, Quota: p.Quota, Expiry: p.Expiry, Enabled: true, Links: []string{"vless://" + p.UUID + "@remote.example:443?type=ws&security=tls&path=%2Fconnect%2Ftest%2F"}, Subscription: "https://remote.example/sub/" + p.SubID}
			r.users[p.Email] = v
			if r.failAfterCreate {
				r.failAfterCreate = false
				http.Error(w, "lost response", 503)
				return
			}
			jsonReply(w, 200, v)
			return
		}
		email := strings.TrimPrefix(req.URL.Path, "/api/v1/clients/")
		v, ok := r.users[email]
		if !ok {
			http.NotFound(w, req)
			return
		}
		if req.Method == "POST" {
			var input struct {
				Quota   int64 `json:"quota"`
				Expiry  int64 `json:"expiry"`
				Enabled bool  `json:"enabled"`
			}
			_ = json.NewDecoder(req.Body).Decode(&input)
			v.Quota = input.Quota
			v.Expiry = input.Expiry
			v.Enabled = input.Enabled
			r.users[email] = v
		}
		jsonReply(w, 200, v)
	}))
	t.Cleanup(r.server.Close)
	return r
}
func poolFixture411(t *testing.T) (*App, *poolRemote411, *poolRemote411, string) {
	t.Setenv("ARIA_ALLOW_PRIVATE_PANELS", "true")
	a, c := salesFixture(t)
	src, dst := newPoolRemote411(t), newPoolRemote411(t)
	now := time.Now().UnixMilli()
	old := SoldService{ID: "s-pool-fixture", OrderID: "o-pool-fixture", CustomerID: c.ID, PlanID: "p-test", PoolID: "pool-fixture", NodeID: "n-src", Email: "old-email", Name: "سرویس آزمایشی", Subscription: "https://source.example/sub", Links: []string{"vless://00000000-0000-4000-8000-000000000001@source.example:443?type=ws&security=tls"}, Quota: 5 * (1 << 30), Used: 1 << 30, RemoteQuota: 5 * (1 << 30), RemoteUsed: 1 << 30, Expiry: now + 86400000, Enabled: true, UsageChecked: now, StableToken: randomToken(24)}
	src.users[old.Email] = old
	if err := a.salesTxn(func(s *SalesData) error {
		s.Nodes = []PanelNode{{ID: "n-src", Name: "مبدأ", Type: "aria", URL: src.server.URL, Token: "fixture-token", Enabled: true}, {ID: "n-dst", Name: "جایگزین", Type: "aria", URL: dst.server.URL, Token: "fixture-token", Enabled: true}}
		s.Pools = []PanelPool{{ID: "pool-fixture", Name: "گروه آزمایشی", NodeIDs: []string{"n-src", "n-dst"}, Enabled: true}}
		s.PoolSettings = defaultPoolSettings()
		s.PoolSettings.Enabled = true
		s.Budgets = []NodeBudget{{NodeID: "n-src", Limit: 100 * (1 << 30), Ready: true, LastChecked: now}, {NodeID: "n-dst", Limit: 100 * (1 << 30), Ready: true, LastChecked: now}}
		s.Plans[0].PoolID = "pool-fixture"
		s.Services = []SoldService{old}
		s.Orders = []SalesOrder{{ID: old.OrderID, CustomerID: c.ID, PlanID: "p-test", Plan: s.Plans[0], Provision: newProvision(old.Name, 5, 1, []string{"vless-ws"}), Status: "fulfilled", ServiceID: old.ID}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	a.poolProbe = func(context.Context, SoldService) ProbeResult { return ProbeResult{State: "ok", MS: 12} }
	return a, src, dst, old.ID
}
func TestPool411TransferJournalRestartRemainingVolumeAndRenewal(t *testing.T) {
	a, src, dst, id := poolFixture411(t)
	dst.failAfterCreate = true
	if err := a.beginTransfer(context.Background(), id, "قطعی دو ساعت"); err == nil {
		t.Fatal("lost create response should remain pending")
	}
	s := a.salesSnapshot()
	if len(s.Transfers) != 1 || s.Transfers[0].State != "provision" || s.Services[0].NodeID != "n-src" || dst.creates != 1 || len(s.Notices) != 0 {
		t.Fatal("unsafe early delivery", s.Transfers)
	}
	if src.users["old-email"].Enabled {
		t.Fatal("source must be frozen before allocation")
	}
	b, err := NewApp(a.cfg, a.base)
	if err != nil {
		t.Fatal(err)
	}
	b.poolProbe = a.poolProbe
	if err = b.resumeTransfer(context.Background(), s.Transfers[0].ID); err != nil {
		t.Fatal(err)
	}
	if err = b.resumeTransfer(context.Background(), s.Transfers[0].ID); err != nil {
		t.Fatal(err)
	}
	n := b.salesSnapshot()
	v := n.Services[0]
	if dst.creates != 1 || v.Quota != 5*(1<<30) || v.RemoteQuota != 4*(1<<30) || v.CarryUsed != 1<<30 || v.Used != 1<<30 || v.Expiry != s.Services[0].Expiry || v.NodeID != "n-dst" {
		t.Fatal("quota, identity or expiry not preserved", v)
	}
	if n.Transfers[0].State != "complete" || len(n.Notices) < 4 {
		t.Fatal("delivery queue missing")
	}
	seen := map[string]bool{}
	for _, x := range n.Notices {
		if seen[x.ID] {
			t.Fatal("duplicate delivery")
		}
		seen[x.ID] = true
	}
	pub, _ := json.Marshal(b.poolPublic())
	if strings.Contains(string(pub), n.Transfers[0].Input.Password) || strings.Contains(string(pub), n.Transfers[0].Input.UUID) {
		t.Fatal("transfer credentials leaked")
	}
	request := httptest.NewRequest("GET", "/service-sub/"+v.StableToken, nil)
	w := httptest.NewRecorder()
	b.ServeHTTP(w, request)
	decoded, e := base64.StdEncoding.DecodeString(w.Body.String())
	if e != nil || !strings.Contains(string(decoded), n.Transfers[0].Input.UUID) {
		t.Fatal("stable URL did not follow service move")
	}
	dst.mu.Lock()
	cur := dst.users[v.Email]
	cur.Used = 2 << 30
	dst.users[v.Email] = cur
	dst.mu.Unlock()
	live, err := b.syncSoldService(context.Background(), id)
	if err != nil || live.Used != 3*(1<<30) || live.Quota != 5*(1<<30) {
		t.Fatal("carry accounting lost", live, err)
	}
	_ = b.salesTxn(func(s *SalesData) error { s.Customers[0].Balance = 100000; s.Plans[0].QuotaGB = 2; return nil })
	o, err := b.newOrder(BuyRequest{CustomerID: v.CustomerID, ServiceID: v.ID, PlanID: "p-test", Kind: "renew", Method: "wallet", Idempotency: "renew-after-move"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = b.fulfillOrder(context.Background(), o.ID)
	if err != nil {
		t.Fatal(err)
	}
	v = b.salesSnapshot().Services[0]
	if v.NodeID != "n-dst" || v.PoolID != "pool-fixture" || v.Quota != 7*(1<<30) || v.Used != 3*(1<<30) || v.CarryUsed != 1<<30 {
		t.Fatal("renewal after move lost allowance", v)
	}
}
func TestPool411OfflineSourceOptInAndCleanup(t *testing.T) {
	a, src, dst, id := poolFixture411(t)
	src.offline = true
	if e := a.beginTransfer(context.Background(), id, "host down"); e == nil {
		t.Fatal("offline source estimated by default")
	}
	if dst.creates != 0 {
		t.Fatal("offline move created target without permission")
	}
	_ = a.salesTxn(func(s *SalesData) error { s.PoolSettings.AllowOfflineSource = true; return nil })
	tr := a.salesSnapshot().Transfers[0]
	if e := a.resumeTransfer(context.Background(), tr.ID); e != nil {
		t.Fatal(e)
	}
	s := a.salesSnapshot()
	v := s.Services[0]
	if !s.Transfers[0].Offline || !s.Transfers[0].CleanupPending || v.RemoteQuota != 4*(1<<30)-4*(1<<30)*10/100 {
		t.Fatal("estimated remaining quota or cleanup lost", v)
	}
	src.mu.Lock()
	src.offline = false
	src.mu.Unlock()
	if e := a.resumeTransfer(context.Background(), tr.ID); e != nil {
		t.Fatal(e)
	}
	if a.salesSnapshot().Transfers[0].CleanupPending || src.users["old-email"].Enabled {
		t.Fatal("old source not disabled after recovery")
	}
}
func TestPool411UnverifiedTargetNoDeliveryAndRetrySameIdentity(t *testing.T) {
	a, _, dst, id := poolFixture411(t)
	a.poolProbe = func(context.Context, SoldService) ProbeResult { return ProbeResult{State: "down"} }
	if e := a.beginTransfer(context.Background(), id, "probe outage"); e == nil {
		t.Fatal("failed target accepted")
	}
	s := a.salesSnapshot()
	if len(s.Notices) != 0 || s.Services[0].NodeID != "n-src" {
		t.Fatal("bad target delivered")
	}
	a.poolProbe = func(context.Context, SoldService) ProbeResult { return ProbeResult{State: "ok"} }
	if e := a.resumeTransfer(context.Background(), s.Transfers[0].ID); e != nil {
		t.Fatal(e)
	}
	if dst.creates != 1 {
		t.Fatal("retry provisioned duplicate account")
	}
}
func TestPool411CancelRevokesUndeliveredTarget(t *testing.T) {
	a, src, dst, id := poolFixture411(t)
	a.poolProbe = func(context.Context, SoldService) ProbeResult { return ProbeResult{State: "down"} }
	if e := a.beginTransfer(context.Background(), id, "fixture"); e == nil {
		t.Fatal("target unexpectedly verified")
	}
	tr := a.salesSnapshot().Transfers[0]
	if e := a.cancelTransfer(context.Background(), tr.ID); e != nil {
		t.Fatal(e)
	}
	if !src.users[tr.OldEmail].Enabled || dst.users[tr.Input.Email].Enabled || transferOpenCopy411(a, id) {
		t.Fatal("cancel left double live accounts or pending journal")
	}
}
func transferOpenCopy411(a *App, id string) bool { s := a.salesSnapshot(); return transferOpen(&s, id) }
func TestPool411NewSalesChooseCapacityAndPersistRoute(t *testing.T) {
	a, src, dst, _ := poolFixture411(t)
	_ = a.salesTxn(func(s *SalesData) error {
		s.Customers[0].Balance = 100000
		s.Budgets[0].Used = s.Budgets[0].Limit
		return nil
	})
	s := a.salesSnapshot()
	o, e := a.newOrder(BuyRequest{CustomerID: s.Customers[0].ID, PlanID: "p-test", Kind: "buy", Method: "wallet", Idempotency: "pool-new-buy"})
	if e != nil {
		t.Fatal(e)
	}
	result, e := a.fulfillOrder(context.Background(), o.ID)
	if e != nil {
		t.Fatal(e)
	}
	if result.Plan.NodeID != "n-dst" || dst.creates != 1 || src.creates != 0 {
		t.Fatal("new order did not avoid exhausted source", result)
	}
	if _, e = a.fulfillOrder(context.Background(), o.ID); e != nil {
		t.Fatal(e)
	}
	if dst.creates != 1 {
		t.Fatal("repeated fulfilment duplicated client")
	}
}
func TestPool411AutomaticTickDoesNotMoveMomentaryFailure(t *testing.T) {
	a, _, dst, id := poolFixture411(t)
	a.poolProbe = func(_ context.Context, v SoldService) ProbeResult {
		if v.Email == "old-email" {
			return ProbeResult{State: "down"}
		}
		return ProbeResult{State: "ok"}
	}
	if e := a.panelPoolTick(context.Background(), true); e != nil {
		t.Fatal(e)
	}
	if dst.creates != 0 {
		t.Fatal("one bad probe moved a customer")
	}
	now := time.Now().UnixMilli()
	_ = a.salesTxn(func(s *SalesData) error {
		i := serviceIndex(s, id)
		s.Services[i].Health = ServiceHealth{State: "down", FailedSince: now - 121*60000, Failures: 24, Checked: now - 300000}
		return nil
	})
	if e := a.panelPoolTick(context.Background(), true); e != nil {
		t.Fatal(e)
	}
	if dst.creates != 1 || a.salesSnapshot().Services[0].NodeID != "n-dst" {
		t.Fatal("two-hour qualified automatic observation did not move customer")
	}
}
func TestPool411CapacityReservationsUnlimitedAndExpiredCustomers(t *testing.T) {
	a, _, _, id := poolFixture411(t)
	s := a.salesSnapshot()
	s.Budgets[1].Limit = 3 * (1 << 30)
	if _, e := choosePoolNode(&s, s.Pools[0], "n-src", 4*(1<<30), id, time.Now().UnixMilli()); e == nil {
		t.Fatal("insufficient host budget accepted")
	}
	if _, e := choosePoolNode(&s, s.Pools[0], "n-src", 0, id, time.Now().UnixMilli()); e == nil {
		t.Fatal("unlimited client on limited host")
	}
	s.Budgets[1].Limit = 6 * (1 << 30)
	s.Services = append(s.Services, SoldService{ID: "reserved", NodeID: "n-dst", Quota: 3 * (1 << 30), Enabled: true})
	if _, e := choosePoolNode(&s, s.Pools[0], "n-src", 4*(1<<30), id, time.Now().UnixMilli()); e == nil {
		t.Fatal("outstanding allocations ignored")
	}
	_ = a.salesTxn(func(s *SalesData) error { s.Services[0].Expiry = time.Now().Add(-time.Hour).UnixMilli(); return nil })
	if e := a.beginTransfer(context.Background(), id, "quota"); e == nil {
		t.Fatal("expired customer got free renewed replacement")
	}
}
func TestPool411MonitorScopeAndProbeParser(t *testing.T) {
	a := testApp(t)
	token := "aria_pk_k-fixture." + strings.Repeat("a", 40)
	_ = a.salesTxn(func(s *SalesData) error {
		s.Keys = []IntegrationKey{{ID: "k-fixture", Hash: hashToken(token), Scopes: []string{"clients:read"}, Expires: time.Now().Add(time.Hour).UnixMilli()}}
		return nil
	})
	call := func() int {
		req := httptest.NewRequest("GET", "/api/v1/pool-status", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		a.ServeHTTP(w, req)
		return w.Code
	}
	if call() != 403 {
		t.Fatal("client key disclosed aggregate node traffic")
	}
	_ = a.salesTxn(func(s *SalesData) error { s.Keys[0].Scopes = append(s.Keys[0].Scopes, "monitor:read"); return nil })
	if call() != 200 {
		t.Fatal("monitor scope not supported")
	}
	for _, network := range []string{"tcp", "ws", "xhttp", "grpc", "httpupgrade"} {
		uri := fmt.Sprintf("vless://00000000-0000-4000-8000-000000000001@public.example:443?security=tls&type=%s&path=%%2Fconnect%%2Ftest%%2F", network)
		o, h, e := poolOutbound(uri)
		if e != nil || h != "public.example" || o["protocol"] != "vless" {
			t.Fatal(network, e)
		}
	}
	for _, suffix := range []string{"&allowInsecure=1", "&extra=%7B%7D"} {
		if _, _, e := poolOutbound("vless://00000000-0000-4000-8000-000000000001@public.example:443?type=ws&security=tls" + suffix); e == nil {
			t.Fatal("unsafe probe executed")
		}
	}
	if _, _, e := poolOutbound("hy2://password@public.example:443"); e == nil {
		t.Fatal("unsupported protocol reported as failed TCP")
	}
}
