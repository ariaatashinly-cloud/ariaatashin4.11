package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// All timestamps are milliseconds. Commerce's atomic journal also records
// remote work before it is attempted, so a restart never creates a new identity.
type PoolSettings struct {
	Enabled               bool `json:"enabled"`
	IntervalSeconds       int  `json:"intervalSeconds"`
	FailAfterMinutes      int  `json:"failAfterMinutes"`
	CooldownMinutes       int  `json:"cooldownMinutes"`
	AllowOfflineSource    bool `json:"allowOfflineSource"`
	OfflineReservePercent int  `json:"offlineReservePercent"`
}
type PanelPool struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	NodeIDs []string `json:"nodeIds"`
	Enabled bool     `json:"enabled"`
}
type NodeBudget struct {
	NodeID          string `json:"nodeId"`
	Limit           int64  `json:"limit"`
	Used            int64  `json:"used"`
	Reserve         int64  `json:"reserve"`
	ResetAt         int64  `json:"resetAt"`
	Counter         int64  `json:"counter"`
	CounterKnown    bool   `json:"counterKnown"`
	LastChecked     int64  `json:"lastChecked"`
	Ready           bool   `json:"ready"`
	Note            string `json:"note"`
	ExhaustedSince  int64  `json:"exhaustedSince"`
	ExhaustedChecks int    `json:"exhaustedChecks"`
}
type ServiceHealth struct {
	State        string `json:"state"`
	Note         string `json:"note"`
	Checked      int64  `json:"checked"`
	FailedSince  int64  `json:"failedSince"`
	Failures     int    `json:"failures"`
	LatencyMS    int64  `json:"latencyMS"`
	LastTransfer int64  `json:"lastTransfer"`
}
type ProbeResult struct {
	State string
	Note  string
	MS    int64
}
type ServiceTransfer struct {
	ID             string         `json:"id"`
	ServiceID      string         `json:"serviceId"`
	From           string         `json:"from"`
	To             string         `json:"to"`
	OldEmail       string         `json:"oldEmail"`
	OldQuota       int64          `json:"oldQuota"`
	OldExpiry      int64          `json:"oldExpiry"`
	Carry          int64          `json:"carry"`
	Input          ProvisionInput `json:"input"`
	State          string         `json:"state"`
	Reason         string         `json:"reason"`
	Note           string         `json:"note"`
	Created        int64          `json:"created"`
	Updated        int64          `json:"updated"`
	SourceFrozen   bool           `json:"sourceFrozen"`
	Offline        bool           `json:"offline"`
	CleanupPending bool           `json:"cleanupPending"`
}

func defaultPoolSettings() PoolSettings {
	return PoolSettings{IntervalSeconds: 300, FailAfterMinutes: 120, CooldownMinutes: 120, OfflineReservePercent: 10}
}
func validPoolSettings(s PoolSettings) bool {
	return s.IntervalSeconds >= 60 && s.IntervalSeconds <= 3600 && s.FailAfterMinutes >= 10 && s.FailAfterMinutes <= 1440 && s.CooldownMinutes >= 30 && s.CooldownMinutes <= 10080 && s.OfflineReservePercent >= 0 && s.OfflineReservePercent <= 50
}
func normalizePoolData(s *SalesData) {
	if s.PoolSettings.IntervalSeconds == 0 {
		s.PoolSettings = defaultPoolSettings()
	}
	if !validPoolSettings(s.PoolSettings) {
		s.PoolSettings = defaultPoolSettings()
	}
	// A gap with no measurements is not evidence of continuous downtime.
	for i := range s.Services {
		s.Services[i].Health.FailedSince = 0
		s.Services[i].Health.Failures = 0
		s.Services[i].Health.Checked = 0
	}
	for i := range s.Budgets {
		s.Budgets[i].ExhaustedChecks = 0
		s.Budgets[i].ExhaustedSince = 0
		s.Budgets[i].LastChecked = 0
	}
}
func poolIndex(s *SalesData, id string) int {
	for i, p := range s.Pools {
		if p.ID == id {
			return i
		}
	}
	return -1
}
func budgetIndex(s *SalesData, id string) int {
	for i, b := range s.Budgets {
		if b.NodeID == id {
			return i
		}
	}
	return -1
}
func transferIndex(s *SalesData, id string) int {
	for i, t := range s.Transfers {
		if t.ID == id {
			return i
		}
	}
	return -1
}
func poolNodeID(id string) string {
	if id == "" {
		return "local"
	}
	return id
}
func poolContains(p PanelPool, id string) bool {
	id = poolNodeID(id)
	for _, n := range p.NodeIDs {
		if n == id {
			return true
		}
	}
	return false
}
func transferOpen(s *SalesData, id string) bool {
	for _, t := range s.Transfers {
		if t.ServiceID == id && transferPending(t) {
			return true
		}
	}
	return false
}
func transferPending(t ServiceTransfer) bool { return t.State != "complete" && t.State != "cancelled" }
func activeSale(v SoldService, now int64) bool {
	return v.Enabled && (v.Expiry == 0 || v.Expiry > now) && (v.Quota == 0 || v.Used < v.Quota)
}
func budgetExhausted(b NodeBudget) bool { return b.Limit > 0 && b.Used >= b.Limit-b.Reserve }
func advanceHealth(h ServiceHealth, r ProbeResult, now int64, cfg PoolSettings) ServiceHealth {
	if h.Checked == 0 || now-h.Checked > int64(cfg.IntervalSeconds)*3000 {
		h.FailedSince = 0
		h.Failures = 0
	}
	h.Checked = now
	h.State = r.State
	h.Note = r.Note
	h.LatencyMS = r.MS
	if r.State == "down" {
		if h.FailedSince == 0 {
			h.FailedSince = now
		}
		h.Failures++
	} else {
		h.FailedSince = 0
		h.Failures = 0
	}
	return h
}
func healthTransferDue(h ServiceHealth, now int64, cfg PoolSettings) bool {
	return h.State == "down" && h.Failures >= 3 && h.FailedSince > 0 && now-h.FailedSince >= int64(cfg.FailAfterMinutes)*60000 && now-h.Checked <= int64(cfg.IntervalSeconds)*2000 && (h.LastTransfer == 0 || now-h.LastTransfer >= int64(cfg.CooldownMinutes)*60000)
}
func (a *App) poolPublic() any {
	s := a.salesSnapshot()
	rows := []any{}
	for _, t := range s.Transfers {
		rows = append(rows, map[string]any{"id": t.ID, "serviceId": t.ServiceID, "from": t.From, "to": t.To, "state": t.State, "reason": t.Reason, "note": t.Note, "created": t.Created, "updated": t.Updated, "offline": t.Offline, "cleanupPending": t.CleanupPending})
	}
	if len(rows) > 100 {
		rows = rows[len(rows)-100:]
	}
	return map[string]any{"settings": s.PoolSettings, "pools": s.Pools, "budgets": s.Budgets, "transfers": rows, "scope": "panel-server"}
}
func (a *App) poolAPI(w http.ResponseWriter, r *http.Request, path string) {
	if path == "/pool" && r.Method == "GET" {
		jsonReply(w, 200, a.poolPublic())
		return
	}
	if r.Method != "POST" {
		apiError(w, 405, "POST لازم است")
		return
	}
	var err error
	switch path {
	case "/pool/settings":
		var v PoolSettings
		if readBody(w, r, &v, 2048) != nil || !validPoolSettings(v) {
			apiError(w, 400, "فاصلهٔ بررسی ۶۰ تا ۳۶۰۰ ثانیه، قطعی ۱۰ تا ۱۴۴۰ دقیقه و توقف تعویض ۳۰ تا ۱۰۰۸۰ دقیقه لازم است")
			return
		}
		err = a.salesTxn(func(s *SalesData) error {
			s.PoolSettings = v
			for i := range s.Services {
				s.Services[i].Health.FailedSince = 0
				s.Services[i].Health.Failures = 0
			}
			return nil
		})
	case "/pool/groups":
		var v PanelPool
		if readBody(w, r, &v, 4096) != nil || !safeLabel(v.Name, 64) || len(v.NodeIDs) < 2 || len(v.NodeIDs) > 20 {
			apiError(w, 400, "گروه با نام و ۲ تا ۲۰ پنل به‌ترتیب اولویت لازم است")
			return
		}
		err = a.salesTxn(func(s *SalesData) error {
			seen := map[string]bool{}
			for _, id := range v.NodeIDs {
				if seen[id] || (id != "local" && nodeIndex(s, id) < 0) {
					return fmt.Errorf("پنل تکراری یا ناشناخته است")
				}
				seen[id] = true
			}
			if v.ID == "" {
				if len(s.Pools) >= 30 {
					return fmt.Errorf("سقف ۳۰ گروه")
				}
				v.ID = "pool-" + randomToken(6)
				s.Pools = append(s.Pools, v)
			} else {
				i := poolIndex(s, v.ID)
				if i < 0 {
					return fmt.Errorf("گروه یافت نشد")
				}
				for _, svc := range s.Services {
					if svc.PoolID == v.ID && !poolContains(v, svc.NodeID) {
						return fmt.Errorf("پنل دارای مشتری را از گروه حذف نکن")
					}
				}
				s.Pools[i] = v
			}
			return nil
		})
	case "/pool/budget":
		var v NodeBudget
		if readBody(w, r, &v, 2048) != nil || v.Limit < 0 || v.Limit > 1e6*(1<<30) || v.Used < 0 || v.Used > 1e6*(1<<30) || v.Reserve < 0 || v.Reserve > v.Limit || v.ResetAt < 0 {
			apiError(w, 400, "سهمیه و مصرف میزبان معتبر نیست")
			return
		}
		err = a.salesTxn(func(s *SalesData) error {
			if v.NodeID != "local" && nodeIndex(s, v.NodeID) < 0 {
				return fmt.Errorf("پنل یافت نشد")
			}
			i := budgetIndex(s, v.NodeID)
			if i >= 0 {
				old := s.Budgets[i]
				v.Counter = old.Counter
				v.CounterKnown = false
				v.LastChecked = old.LastChecked
				v.Ready = old.Ready
				v.Note = old.Note
			}
			if i < 0 {
				s.Budgets = append(s.Budgets, v)
			} else {
				s.Budgets[i] = v
			}
			return nil
		})
	case "/pool/check":
		ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
		defer cancel()
		err = a.panelPoolTick(ctx, true)
	default:
		parts := strings.Split(strings.Trim(path, "/"), "/")
		if len(parts) == 4 && parts[0] == "pool" && parts[1] == "transfers" && parts[3] == "cancel" {
			job, cancel := context.WithTimeout(r.Context(), 30*time.Second)
			defer cancel()
			err = a.cancelTransfer(job, parts[2])
		} else {
			apiError(w, 404, "عملیات گروه پنل یافت نشد")
			return
		}
	}
	if err != nil {
		apiError(w, 400, err.Error())
		return
	}
	jsonReply(w, 200, map[string]any{"ok": true, "pool": a.poolPublic()})
}
func (a *App) assignServicePool(id, pool string) error {
	a.fulfillMu.Lock()
	defer a.fulfillMu.Unlock()
	return a.salesTxn(func(s *SalesData) error {
		i := serviceIndex(s, id)
		if i < 0 {
			return fmt.Errorf("سرویس یافت نشد")
		}
		if transferOpen(s, id) {
			return fmt.Errorf("ابتدا انتقال در جریان را کامل کن")
		}
		if pool != "" {
			pi := poolIndex(s, pool)
			if pi < 0 || !poolContains(s.Pools[pi], s.Services[i].NodeID) {
				return fmt.Errorf("پنل فعلی سرویس باید عضو گروه باشد")
			}
		}
		s.Services[i].PoolID = pool
		s.Services[i].Health = ServiceHealth{}
		if s.Services[i].StableToken == "" {
			s.Services[i].StableToken = randomToken(24)
		}
		return nil
	})
}
func (a *App) poolSubscription(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != "GET" {
		http.Error(w, "method not allowed", 405)
		return
	}
	token := strings.TrimPrefix(r.URL.Path, "/service-sub/")
	if len(token) != 48 {
		http.NotFound(w, r)
		return
	}
	s := a.salesSnapshot()
	for _, v := range s.Services {
		if v.StableToken != token {
			continue
		}
		ci := customerIndex(&s, v.CustomerID)
		if ci < 0 || s.Customers[ci].Blocked || !activeSale(v, time.Now().UnixMilli()) {
			http.Error(w, "service inactive", 403)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Subscription-Userinfo", fmt.Sprintf("upload=0; download=%d; total=%d; expire=%d", v.Used, v.Quota, v.Expiry/1000))
		fmt.Fprint(w, base64.StdEncoding.EncodeToString([]byte(strings.Join(v.Links, "\n"))))
		return
	}
	http.NotFound(w, r)
}
func (a *App) stableSaleURL(v SoldService) string {
	if v.StableToken == "" {
		return v.Subscription
	}
	origin := a.snapshot().Settings.PublicURL
	if origin == "" {
		return v.Subscription
	}
	return origin + "/service-sub/" + v.StableToken
}

// Reservations account for unused customer allocations, pending paid orders
// and journaled moves; they avoid selling the same remaining hosting bytes twice.
func nodeReserved(s *SalesData, node, except string) int64 {
	var n int64
	node = poolNodeID(node)
	now := time.Now().UnixMilli()
	for _, v := range s.Services {
		if v.ID != except && poolNodeID(v.NodeID) == node && activeSale(v, now) && v.Quota > 0 {
			n += max(int64(0), v.Quota-v.Used)
		}
	}
	for _, o := range s.Orders {
		if o.Kind != "renew" && o.Kind != "topup" && o.Provision.OperationID != except && poolNodeID(o.Plan.NodeID) == node && (o.Status == "paid" || o.Status == "provisioning" || o.Status == "uncertain") {
			n += o.Provision.Quota
		}
	}
	for _, t := range s.Transfers {
		if t.ServiceID != except && transferPending(t) && poolNodeID(t.To) == node {
			n += t.Input.Quota
		}
	}
	return n
}
func choosePoolNode(s *SalesData, p PanelPool, skip string, quota int64, except string, now int64) (string, error) {
	if !p.Enabled {
		return "", fmt.Errorf("گروه پنل غیرفعال است")
	}
	for _, id := range p.NodeIDs {
		if skip != "" && id == poolNodeID(skip) {
			continue
		}
		if id != "local" {
			i := nodeIndex(s, id)
			if i < 0 || !s.Nodes[i].Enabled {
				continue
			}
		}
		bi := budgetIndex(s, id)
		if bi < 0 {
			continue
		}
		b := s.Budgets[bi]
		if !b.Ready || b.LastChecked == 0 || now-b.LastChecked > int64(s.PoolSettings.IntervalSeconds)*3000 {
			continue
		}
		bad := false
		for _, v := range s.Services {
			if poolNodeID(v.NodeID) == id && v.Health.State == "down" && now-v.Health.Checked < int64(s.PoolSettings.IntervalSeconds)*3000 {
				bad = true
			}
		}
		if bad {
			continue
		}
		if b.Limit > 0 && (quota == 0 || budgetExhausted(b) || quota > max(int64(0), b.Limit-b.Reserve-b.Used-nodeReserved(s, id, except))) {
			continue
		}
		return id, nil
	}
	return "", fmt.Errorf("پنل سالم با ظرفیت کافی در گروه یافت نشد؛ آزمایش اتصال و سهمیه‌ها را بررسی کن")
}
func (a *App) routePoolOrder(ctx context.Context, o SalesOrder) (SalesOrder, error) {
	if o.Plan.PoolID == "" || o.Kind == "renew" || o.Plan.NodeID != "" {
		return o, nil
	}
	s := a.salesSnapshot()
	pi := poolIndex(&s, o.Plan.PoolID)
	if pi < 0 {
		return o, fmt.Errorf("گروه پنل یافت نشد")
	}
	for _, id := range s.Pools[pi].NodeIDs {
		_ = a.refreshPoolNode(ctx, id)
	}
	err := a.salesTxn(func(s *SalesData) error {
		i := orderIndex(s, o.ID)
		if s.Orders[i].Plan.NodeID != "" {
			o = s.Orders[i]
			return nil
		}
		node, e := choosePoolNode(s, s.Pools[poolIndex(s, o.Plan.PoolID)], "", o.Provision.Quota, o.Provision.OperationID, time.Now().UnixMilli())
		if e != nil {
			return e
		}
		s.Orders[i].Plan.NodeID = node
		o = s.Orders[i]
		return nil
	})
	return o, err
}

// monitor:read is separate from client ownership; it reveals only aggregate
// traffic and readiness, never credentials, customer names or account links.
func (a *App) localPoolStatus() map[string]any {
	s := a.snapshot()
	var used int64
	for _, u := range s.Users {
		used += max(int64(0), u.Up+u.Down)
	}
	return map[string]any{"ready": s.Ready, "traffic": used, "source": "xray-client-counters"}
}
func (a *App) refreshPoolNode(ctx context.Context, id string) error {
	id = poolNodeID(id)
	var used int64
	ready := false
	note := ""
	var err error
	if id == "local" {
		err = a.refresh(ctx)
		if err == nil {
			s := a.snapshot()
			ready = s.Ready
			for _, u := range s.Users {
				used += max(int64(0), u.Up+u.Down)
			}
		}
	} else {
		n, e := a.node(id)
		err = e
		if err == nil {
			switch n.Type {
			case "aria":
				var v struct {
					Ready   bool  `json:"ready"`
					Traffic int64 `json:"traffic"`
				}
				err = remoteRequest(ctx, a.nodeClient(), n, "GET", "/api/v1/pool-status", nil, map[string]string{"Authorization": "Bearer " + n.Token}, &v)
				ready = v.Ready
				used = v.Traffic
			case "marzban":
				h, e := a.marzAuth(ctx, n)
				err = e
				if e == nil {
					var v struct {
						Used *int64 `json:"incoming_bandwidth"`
						Out  *int64 `json:"outgoing_bandwidth"`
					}
					err = remoteRequest(ctx, a.nodeClient(), n, "GET", "/api/system", nil, h, &v)
					if err == nil {
						if v.Used == nil || v.Out == nil || *v.Used < 0 || *v.Out < 0 {
							err = fmt.Errorf("شمارندهٔ ترافیک Marzban معتبر نیست")
						} else {
							used = *v.Used + *v.Out
						}
					}
					ready = err == nil
				}
			case "3x-ui":
				e, e2 := a.remoteEngine(ctx, n)
				err = e2
				if err == nil {
					all, e3 := e.inbounds(ctx)
					err = e3
					seen := map[string]int64{}
					for _, ib := range all {
						for _, v := range ib.Stats {
							seen[v.Email] = max(seen[v.Email], v.Up+v.Down)
						}
					}
					for _, v := range seen {
						used += max(int64(0), v)
					}
					ready = err == nil
				}
			}
		}
	}
	if err != nil {
		note = "آمار میزبان دریافت نشد؛ اتصال، نسخهٔ ۴.۱۱ و دسترسی monitor:read را بررسی کن"
	} else if !ready {
		note = "هستهٔ مقصد هنوز آماده نیست"
	}
	now := time.Now().UnixMilli()
	save := a.salesTxn(func(s *SalesData) error {
		i := budgetIndex(s, id)
		if i < 0 {
			s.Budgets = append(s.Budgets, NodeBudget{NodeID: id})
			i = len(s.Budgets) - 1
		}
		b := &s.Budgets[i]
		if b.ResetAt > 0 && now >= b.ResetAt {
			b.Used = 0
			b.CounterKnown = false
			b.ExhaustedSince = 0
			b.ExhaustedChecks = 0
			b.ResetAt = 0
		}
		if err == nil && used >= 0 {
			if b.CounterKnown {
				delta := used - b.Counter
				if delta < 0 {
					delta = used
				}
				if delta > 0 {
					b.Used += delta
				}
			}
			b.Counter = used
			b.CounterKnown = true
		}
		if now-b.LastChecked > int64(s.PoolSettings.IntervalSeconds)*3000 {
			b.ExhaustedSince = 0
			b.ExhaustedChecks = 0
		}
		b.Ready = ready && err == nil
		b.Note = note
		b.LastChecked = now
		if budgetExhausted(*b) && err == nil {
			if b.ExhaustedSince == 0 {
				b.ExhaustedSince = now
			}
			b.ExhaustedChecks++
		} else {
			b.ExhaustedChecks = 0
			b.ExhaustedSince = 0
		}
		return nil
	})
	if save != nil {
		return save
	}
	return err
}

func (a *App) panelPoolLoop(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = a.panelPoolTick(ctx, false)
		}
	}
}
func (a *App) panelPoolTick(ctx context.Context, manual bool) error {
	if !a.poolCheckMu.TryLock() {
		return fmt.Errorf("بررسی دیگری در جریان است")
	}
	defer a.poolCheckMu.Unlock()
	s := a.salesSnapshot()
	if !manual && !s.PoolSettings.Enabled {
		return nil
	}
	now := time.Now().UnixMilli()
	ids := map[string]bool{}
	for _, p := range s.Pools {
		if p.Enabled {
			for _, id := range p.NodeIDs {
				ids[id] = true
			}
		}
	}
	for id := range ids {
		bi := budgetIndex(&s, id)
		if manual || bi < 0 || now-s.Budgets[bi].LastChecked >= int64(s.PoolSettings.IntervalSeconds)*1000 {
			job, c := context.WithTimeout(ctx, 10*time.Second)
			_ = a.refreshPoolNode(job, id)
			c()
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	// Reconcile pending moves and revoke a formerly offline source on recovery.
	for _, tr := range a.salesSnapshot().Transfers {
		if transferPending(tr) || tr.CleanupPending {
			job, c := context.WithTimeout(ctx, 35*time.Second)
			_ = a.resumeTransfer(job, tr.ID)
			c()
			break
		}
	}
	s = a.salesSnapshot()
	if len(s.Services) == 0 {
		return nil
	}
	count := 0
	start := a.poolCursor % len(s.Services)
	for offset := 0; offset < len(s.Services); offset++ {
		i := (start + offset) % len(s.Services)
		v := s.Services[i]
		a.poolCursor = i + 1
		if v.PoolID == "" || !activeSale(v, now) || transferOpen(&s, v.ID) {
			continue
		}
		pi := poolIndex(&s, v.PoolID)
		if pi < 0 || !s.Pools[pi].Enabled {
			continue
		}
		if !manual && now-v.Health.Checked < int64(s.PoolSettings.IntervalSeconds)*1000 {
			continue
		}
		job, c := context.WithTimeout(ctx, 25*time.Second)
		a.fulfillMu.Lock()
		live, err := a.syncSoldServiceLocked(job, v.ID)
		a.fulfillMu.Unlock()
		if err == nil {
			v = live
		}
		r := ProbeResult{State: "unknown", Note: "لینک قابل آزمایش آماده نیست"}
		if activeSale(v, now) {
			if a.poolProbe != nil {
				r = a.poolProbe(job, v)
			} else {
				r = a.probeSale(job, v)
			}
		}
		c()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil && r.State != "ok" {
			r.Note += "؛ مصرف جدید مبدأ دریافت نشد"
		}
		var due bool
		reason := "قطعی پیوستهٔ اتصال"
		if e := a.salesTxn(func(s *SalesData) error {
			i := serviceIndex(s, v.ID)
			if i < 0 || s.Services[i].Email != v.Email {
				return nil
			}
			h := advanceHealth(s.Services[i].Health, r, time.Now().UnixMilli(), s.PoolSettings)
			s.Services[i].Health = h
			if !s.PoolSettings.Enabled {
				return nil
			}
			due = healthTransferDue(h, time.Now().UnixMilli(), s.PoolSettings)
			bi := budgetIndex(s, poolNodeID(v.NodeID))
			if bi >= 0 {
				b := s.Budgets[bi]
				if b.ExhaustedChecks >= 2 && time.Now().UnixMilli()-b.ExhaustedSince >= 60000 && (h.LastTransfer == 0 || now-h.LastTransfer >= int64(s.PoolSettings.CooldownMinutes)*60000) {
					due = true
					reason = "رسیدن به سقف ترافیک میزبان"
				}
			}
			return nil
		}); e != nil {
			return e
		}
		if due {
			job, c := context.WithTimeout(ctx, 40*time.Second)
			e := a.beginTransfer(job, v.ID, reason)
			c()
			if e != nil {
				_ = a.salesTxn(func(s *SalesData) error {
					if i := serviceIndex(s, v.ID); i >= 0 {
						s.Services[i].Health.Note = e.Error()
					}
					return nil
				})
			}
		}
		count++
		if count >= 4 {
			break
		}
	}
	return nil
}

func (a *App) beginTransfer(ctx context.Context, id, reason string) error {
	a.fulfillMu.Lock()
	defer a.fulfillMu.Unlock()
	s := a.salesSnapshot()
	i := serviceIndex(&s, id)
	if i < 0 {
		return fmt.Errorf("سرویس یافت نشد")
	}
	old := s.Services[i]
	if transferOpen(&s, id) {
		return nil
	}
	if !activeSale(old, time.Now().UnixMilli()) {
		return fmt.Errorf("سرویس غیرفعال، منقضی یا حجم مشتری تمام شده است")
	}
	for _, o := range s.Orders {
		if o.ServiceID == id && o.Status != "fulfilled" && o.Status != "cancelled" {
			return fmt.Errorf("سفارش باز این سرویس را ابتدا کامل کن")
		}
	}
	pi := poolIndex(&s, old.PoolID)
	if pi < 0 {
		return fmt.Errorf("گروه سرویس یافت نشد")
	}
	remaining := int64(0)
	if old.Quota > 0 {
		remaining = old.Quota - old.Used
	}
	node, err := choosePoolNode(&s, s.Pools[pi], poolNodeID(old.NodeID), remaining, id, time.Now().UnixMilli())
	if err != nil {
		return err
	}
	profiles := []string{}
	if oi := orderIndex(&s, old.OrderID); oi >= 0 {
		profiles = s.Orders[oi].Provision.Profiles
	}
	if len(profiles) == 0 {
		if j := planIndex(&s, old.PlanID); j >= 0 {
			profiles = s.Plans[j].Profiles
		}
	}
	if len(profiles) == 0 {
		return fmt.Errorf("الگوی اصلی سرویس یافت نشد")
	}
	p := newProvision(old.Name, float64(remaining)/(1<<30), 0, profiles)
	p.Quota = remaining
	p.Expiry = old.Expiry
	tr := ServiceTransfer{ID: "move-" + p.OperationID, ServiceID: id, From: poolNodeID(old.NodeID), To: node, OldEmail: old.Email, OldQuota: old.RemoteQuota, OldExpiry: old.Expiry, Carry: old.Used, Input: p, State: "prepare", Reason: reason, Created: time.Now().UnixMilli()}
	if old.CarryUsed == 0 {
		tr.OldQuota = old.Quota
	}
	if err = a.salesTxn(func(s *SalesData) error { s.Transfers = append(s.Transfers, tr); return nil }); err != nil {
		return err
	}
	return a.resumeTransferLocked(ctx, tr.ID)
}
func (a *App) resumeTransfer(ctx context.Context, id string) error {
	a.fulfillMu.Lock()
	defer a.fulfillMu.Unlock()
	return a.resumeTransferLocked(ctx, id)
}
func (a *App) transferError(id, note string) error {
	_ = a.salesTxn(func(s *SalesData) error {
		if i := transferIndex(s, id); i >= 0 {
			s.Transfers[i].Note = note
			s.Transfers[i].Updated = time.Now().UnixMilli()
		}
		return nil
	})
	return fmt.Errorf("%s", note)
}
func (a *App) resumeTransferLocked(ctx context.Context, id string) error {
	s := a.salesSnapshot()
	ti := transferIndex(&s, id)
	if ti < 0 {
		return fmt.Errorf("انتقال یافت نشد")
	}
	tr := s.Transfers[ti]
	si := serviceIndex(&s, tr.ServiceID)
	if si < 0 {
		return fmt.Errorf("سرویس یافت نشد")
	}
	old := s.Services[si]
	if tr.State == "cancelled" {
		return nil
	}
	if tr.State == "complete" {
		if tr.CleanupPending {
			e := a.updateRemoteService(ctx, tr.From, tr.OldEmail, tr.OldQuota, tr.OldExpiry, false)
			if e == nil {
				v, e2 := a.getRemoteService(ctx, tr.From, tr.OldEmail)
				if e2 == nil && !v.Enabled {
					_ = a.salesTxn(func(s *SalesData) error { s.Transfers[transferIndex(s, id)].CleanupPending = false; return nil })
				}
			}
		}
		return nil
	}
	if tr.State == "prepare" {
		live, err := a.getRemoteService(ctx, tr.From, tr.OldEmail)
		if err == nil {
			if live.Quota != tr.OldQuota || live.Expiry/1000 != tr.OldExpiry/1000 {
				return a.transferError(id, "سهمیهٔ مبدأ تغییر کرده است؛ انتقال نیازمند بررسی مدیر است")
			}
			if live.Enabled {
				if e := a.updateRemoteService(ctx, tr.From, tr.OldEmail, live.Quota, live.Expiry, false); e != nil {
					return a.transferError(id, "خاموش‌کردن سرویس قبلی تأیید نشد؛ انتقال هنوز انجام نشده است")
				}
			}
			live, err = a.getRemoteService(ctx, tr.From, tr.OldEmail)
			if err != nil || live.Enabled {
				return a.transferError(id, "توقف سرویس قبلی و مصرف نهایی هنوز تأیید نشد")
			}
			tr.Carry = old.CarryUsed + max(old.RemoteUsed, live.Used)
			if old.CarryUsed == 0 {
				tr.Carry = max(old.Used, live.Used)
			}
			tr.SourceFrozen = true
		} else {
			if !s.PoolSettings.AllowOfflineSource || old.UsageChecked == 0 {
				return a.transferError(id, "مبدأ در دسترس نیست؛ مصرف نهایی نامعلوم است. گزینهٔ انتقال با مصرف قبلی را آگاهانه فعال کن یا منتظر بازیابی بمان")
			}
			tr.Offline = true
			tr.CleanupPending = true
			if old.Quota > 0 {
				tr.Carry += ((old.Quota - old.Used) * int64(s.PoolSettings.OfflineReservePercent)) / 100
			}
		}
		if old.Quota > 0 {
			tr.Input.Quota = max(int64(0), old.Quota-tr.Carry)
			if tr.Input.Quota == 0 {
				return a.transferError(id, "حجم باقی‌مانده‌ای برای انتقال وجود ندارد")
			}
		}
		tr.State = "provision"
		tr.Updated = time.Now().UnixMilli()
		if e := a.salesTxn(func(s *SalesData) error { s.Transfers[transferIndex(s, id)] = tr; return nil }); e != nil {
			return e
		}
	}
	if tr.Input.Expiry > 0 && tr.Input.Expiry <= time.Now().UnixMilli() {
		return a.transferError(id, "اعتبار سرویس هنگام انتقال تمام شد؛ تمدید لازم است")
	}
	v, err := a.provisionPlan(ctx, SalesPlan{NodeID: tr.To}, tr.Input)
	if err != nil {
		return a.transferError(id, "ساخت جایگزین تأیید نشد؛ درخواست ثابت ذخیره شده و دوباره بازیابی می‌شود")
	}
	if v.Quota != tr.Input.Quota || v.Expiry/1000 != tr.Input.Expiry/1000 || !v.Enabled || (len(v.Links) == 0 && v.Subscription == "") {
		return a.transferError(id, "حجم، اعتبار یا لینک جایگزین با درخواست مطابقت ندارد")
	}
	r := ProbeResult{}
	if a.poolProbe != nil {
		r = a.poolProbe(ctx, v)
	} else {
		r = a.probeSale(ctx, v)
	}
	if r.State != "ok" {
		return a.transferError(id, "اتصال واقعی جایگزین تأیید نشد؛ سرویس دوم به مشتری تحویل نشده است")
	}
	err = a.salesTxn(func(s *SalesData) error {
		ti := transferIndex(s, id)
		si := serviceIndex(s, tr.ServiceID)
		if s.Transfers[ti].State == "complete" {
			return nil
		}
		previous := s.Services[si]
		if previous.Email != tr.OldEmail {
			return fmt.Errorf("سرویس هم‌زمان تغییر کرده است")
		}
		v.ID = previous.ID
		v.OrderID = previous.OrderID
		v.CustomerID = previous.CustomerID
		v.PlanID = previous.PlanID
		v.PoolID = previous.PoolID
		v.NodeID = tr.To
		v.Created = previous.Created
		v.CarryUsed = tr.Carry
		v.RemoteQuota = v.Quota
		v.RemoteUsed = v.Used
		v.Quota = previous.Quota
		v.Used = tr.Carry + v.Used
		v.UsageChecked = time.Now().UnixMilli()
		v.StableToken = previous.StableToken
		if v.StableToken == "" {
			v.StableToken = randomToken(24)
		}
		v.Reminders = previous.Reminders
		v.Health = ServiceHealth{State: "ok", Checked: time.Now().UnixMilli(), LastTransfer: time.Now().UnixMilli(), LatencyMS: r.MS, Note: "جایگزین از مسیر واقعی تأیید شد"}
		s.Services[si] = v
		tr.State = "complete"
		tr.Note = "تحویل در صف تلگرام"
		tr.Updated = time.Now().UnixMilli()
		s.Transfers[ti] = tr
		ci := customerIndex(s, v.CustomerID)
		if ci >= 0 {
			chat := s.Customers[ci].TelegramID
			addRichNotice(s, id+":notice", chat, "🔄 اتصال جایگزین آماده شد\n"+v.Name+"\nدلیل: "+tr.Reason+"\nاعتبار قبلی حفظ شده است. کانفیگ جدید را وارد کن یا اشتراک را به‌روزرسانی کن.\nاشتراک ثابت:\n"+a.stableSaleURL(v), [][]BotButton{{botButton("سرویس من", "service:"+v.ID)}})
			queueConnectionDelivery(s, id+":links", chat, v.ID, "", len(v.Links))
			addNotice(s, id+":file", chat, "📄 کانفیگ جایگزین "+v.Name)
			for j := range s.Notices {
				if s.Notices[j].ID == id+":file" {
					s.Notices[j].DocumentService = v.ID
				}
			}
		}
		admin := a.telegramSnapshot().ChatID
		addNotice(s, id+":admin", admin, "انتقال سرویس "+v.Name+" از "+tr.From+" به "+tr.To+" ثبت شد."+map[bool]string{true: " مصرف برآوردی است؛ لغو سرویس مبدأ در صف بازیابی است.", false: ""}[tr.Offline])
		return nil
	})
	if err == nil {
		a.audit("انتقال خودکار سرویس "+v.ID, "sale")
		_ = a.persist()
	}
	return err
}

func (a *App) cancelTransfer(ctx context.Context, id string) error {
	a.fulfillMu.Lock()
	defer a.fulfillMu.Unlock()
	s := a.salesSnapshot()
	i := transferIndex(&s, id)
	if i < 0 {
		return fmt.Errorf("انتقال یافت نشد")
	}
	tr := s.Transfers[i]
	if !transferPending(tr) {
		return fmt.Errorf("انتقال در جریان نیست")
	}
	// A possibly created target is revoked before the previous source is restored.
	v, e := a.getRemoteService(ctx, tr.To, tr.Input.Email)
	if e == nil {
		if e = a.updateRemoteService(ctx, tr.To, v.Email, v.Quota, v.Expiry, false); e != nil {
			return fmt.Errorf("توقف جایگزین تأیید نشد")
		}
		v, e = a.getRemoteService(ctx, tr.To, v.Email)
		if e != nil || v.Enabled {
			return fmt.Errorf("توقف جایگزین تأیید نشد")
		}
	} else if !errors.Is(e, errPanelMissing) {
		return fmt.Errorf("وضعیت جایگزین نامعلوم است؛ ابتدا دسترسی مقصد را بازیابی کن")
	}
	live, e := a.getRemoteService(ctx, tr.From, tr.OldEmail)
	if e != nil {
		return fmt.Errorf("مبدأ هنوز در دسترس نیست؛ بازگرداندن آن تأیید نشد")
	}
	if e = a.updateRemoteService(ctx, tr.From, live.Email, live.Quota, live.Expiry, true); e != nil {
		return e
	}
	live, e = a.getRemoteService(ctx, tr.From, tr.OldEmail)
	if e != nil || !live.Enabled {
		return fmt.Errorf("بازگرداندن مبدأ تأیید نشد")
	}
	return a.salesTxn(func(s *SalesData) error {
		i := transferIndex(s, id)
		s.Transfers[i].State = "cancelled"
		s.Transfers[i].CleanupPending = false
		s.Transfers[i].Note = "جایگزین لغو و سرویس مبدأ بازگردانده شد"
		s.Transfers[i].Updated = time.Now().UnixMilli()
		si := serviceIndex(s, tr.ServiceID)
		if si >= 0 {
			s.Services[si].Health = ServiceHealth{LastTransfer: time.Now().UnixMilli(), Note: "انتقال به درخواست مدیر لغو شد"}
		}
		return nil
	})
}

// Read-only stable service URLs point at this controller. They cannot switch
// an already running client without its own subscription refresh behaviour.
