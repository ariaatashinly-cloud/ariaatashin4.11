package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"launcher/internal/cdnscan"
	"os"
	"os/signal"
	"time"
)

func main() {
	jobPath := flag.String("job", "aria-cdn-job.json", "job downloaded from panel")
	out := flag.String("out", "aria-cdn-results.json", "private result file")
	xray := flag.String("xray", "", "optional local Xray executable for real tunnel validation")
	config := flag.String("config", "", "single-connection Xray JSON exported by panel")
	flag.Parse()
	b, e := os.ReadFile(*jobPath)
	if e != nil {
		fail(e)
	}
	var j cdnscan.Job
	if e = json.Unmarshal(b, &j); e != nil {
		fail(e)
	}
	if e = cdnscan.ValidJob(j); e != nil {
		fail(e)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	r := cdnscan.Scan(ctx, j, "client-device", func(v cdnscan.Result) {
		fmt.Printf("%s:%d healthy=%t median=%dms loss=%.0f%%\n", v.IP, v.Port, v.OK, v.MedianMS, v.Loss)
	})
	if *xray != "" || *config != "" {
		if *xray == "" || *config == "" {
			fail(fmt.Errorf("both --xray and --config are required"))
		}
		raw, e := os.ReadFile(*config)
		if e != nil {
			fail(e)
		}
		n := 0
		for i := range r.Results {
			v := &r.Results[i]
			if !v.OK || n >= 16 {
				continue
			}
			n++
			ms, e := cdnscan.ValidateTunnel(ctx, *xray, raw, v.IP)
			v.Tunnel = e == nil
			v.TunnelMS = ms
			fmt.Printf("%s tunnel=%t\n", v.IP, v.Tunnel)
		}
	}
	b, _ = json.MarshalIndent(r, "", "  ")
	if e = os.WriteFile(*out, b, 0600); e != nil {
		fail(e)
	}
	fmt.Println("Saved", *out, "— import in panel; results apply to this device's current network.")
}
func fail(e error) { fmt.Fprintln(os.Stderr, e); os.Exit(1) }
