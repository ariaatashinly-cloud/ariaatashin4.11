//go:build integration

package main

import (
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestNative49PS5BridgeTCPUDPDoH(t *testing.T) {
	bin := os.Getenv("ARIA_TEST_SING_BOX")
	if bin == "" {
		t.Skip("set ARIA_TEST_SING_BOX")
	}
	a, c, _ := dnsFixture46(t)
	server := httptest.NewTLSServer(a)
	defer server.Close()
	config, e := ps5BridgeConfig(server.URL+"/dns-query/"+c.Key, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	config["inbounds"].([]any)[0].(map[string]any)["listen_port"] = port
	// Fixture-only localhost ACL; production exports accept private LAN sources.
	config["route"].(map[string]any)["rules"].([]any)[0].(map[string]any)["source_ip_cidr"] = []string{"127.0.0.0/8"}
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600)
	config["dns"].(map[string]any)["servers"].([]any)[1].(map[string]any)["tls"].(map[string]any)["certificate_path"] = ca
	b, _ := json.Marshal(config)
	file := filepath.Join(dir, "bridge.json")
	os.WriteFile(file, b, 0600)
	if data, e := exec.Command(bin, "check", "-c", file).CombinedOutput(); e != nil {
		t.Fatal(e, string(data))
	}
	cmd := exec.Command(bin, "run", "-c", file)
	log, e := os.Create(filepath.Join(dir, "log"))
	if e != nil {
		t.Fatal(e)
	}
	defer log.Close()
	cmd.Stdout = log
	cmd.Stderr = log
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	for i := 0; i < 50; i++ {
		conn, e := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if e == nil {
			conn.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	for _, network := range []string{"udp", "tcp"} {
		q := new(dns.Msg)
		q.SetQuestion("game.example.", dns.TypeA)
		client := &dns.Client{Net: network, Timeout: 3 * time.Second}
		answer, _, e := client.Exchange(q, addr)
		if e != nil || len(answer.Answer) == 0 || answer.Answer[0].(*dns.A).A.String() != "8.8.4.4" {
			t.Fatal("PS5-style DNS bridge failed", network, e, answer)
		}
	}
}
