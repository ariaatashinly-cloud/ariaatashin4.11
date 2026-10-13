package cdnscan

import (
	"context"
	"testing"
	"time"
)

func TestRangesAndBoundedCandidates(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "8.8.8.8", "::1", "104.16.1.1:443"} {
		if Allowed(s) {
			t.Fatal("outside provider allowed", s)
		}
	}
	for _, s := range []string{"104.16.1.1", "172.64.1.1", "103.21.244.1"} {
		if !Allowed(s) {
			t.Fatal("provider rejected", s)
		}
	}
	v, e := Candidates("104.16.1.0/24", 8)
	if e != nil || len(v) != 8 {
		t.Fatal(v, e)
	}
	v, e = Candidates("", 24)
	if e != nil || len(v) != 24 {
		t.Fatal(e)
	}
	for _, ip := range v {
		if !Allowed(ip) {
			t.Fatal("unsafe random target")
		}
	}
	if _, e = Candidates("0.0.0.0/0", 128); e == nil {
		t.Fatal("internet-wide scan accepted")
	}
}
func TestJobValidationAndCancelledScan(t *testing.T) {
	j := Job{Host: "panel.example", SNI: "panel.example", Port: 443, Identity: "test", IPs: []string{"104.16.1.1"}, Repeats: 3, TimeoutMS: 500, Workers: 1}
	if e := ValidJob(j); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	r := Scan(ctx, j, "client-device", nil)
	if time.Since(start) > time.Second || r.Scope != "client-device" {
		t.Fatal("cancel or scope failed")
	}
	j.IPs = []string{"127.0.0.1"}
	if e := ValidJob(j); e == nil {
		t.Fatal("SSRF target accepted")
	}
}
