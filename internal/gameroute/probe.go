package gameroute

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

func LocalClient(port int, secret string) *http.Client {
	u := &url.URL{Scheme: "http", Host: net.JoinHostPort("127.0.0.1", itoa(port)), User: url.UserPassword("aria", secret)}
	return &http.Client{Timeout: 7 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(u), TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, ForceAttemptHTTP2: false, DisableKeepAlives: true}}
}
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	b := [20]byte{}
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte(n%10) + '0'
		n /= 10
	}
	return string(b[i:])
}
func Probe(ctx context.Context, targets []Target, direct, proxy *http.Client) []Pair {
	pairs := make([]Pair, len(targets))
	var wg sync.WaitGroup
	for i, t := range targets {
		pairs[i].Target = t.URL
		for path, c := range []*http.Client{direct, proxy} {
			wg.Add(1)
			go func(i, path int, t Target, c *http.Client) {
				defer wg.Done()
				out := []Sample{}
				for round := 0; round < 2; round++ {
					out = append(out, probeOne(ctx, t.URL, c))
				}
				if path == 0 {
					pairs[i].Direct = out
				} else {
					pairs[i].Proxy = out
				}
			}(i, path, t, c)
		}
	}
	wg.Wait()
	return pairs
}
func probeOne(ctx context.Context, raw string, original *http.Client) Sample {
	c := *original
	c.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		if len(via) > 3 || r.URL.Scheme != "https" || r.URL.User != nil || r.URL.RawQuery != "" || !strings.EqualFold(strings.TrimPrefix(r.URL.Hostname(), "www."), strings.TrimPrefix(via[0].URL.Hostname(), "www.")) {
			return errors.New("redirect outside test scope")
		}
		return nil
	}
	start := time.Now()
	s := Sample{}
	r, e := http.NewRequestWithContext(ctx, "GET", raw, nil)
	if e != nil {
		s.Error = "network"
		return s
	}
	r.Header.Set("User-Agent", "AriaGameRoute/"+Version)
	r.Header.Set("Cache-Control", "no-cache")
	response, e := c.Do(r)
	s.MS = time.Since(start).Milliseconds()
	if s.MS > 30000 {
		s.MS = 30000
	}
	if e != nil {
		s.Error = "network"
		var ne net.Error
		var te *tls.CertificateVerificationError
		if errors.As(e, &ne) && ne.Timeout() {
			s.Error = "timeout"
		} else if errors.As(e, &te) {
			s.Error = "tls"
		} else if strings.Contains(e.Error(), "redirect outside") {
			s.Error = "redirect"
		}
		if response != nil {
			response.Body.Close()
		}
		return s
	}
	s.Status = response.StatusCode
	_, _ = io.CopyN(io.Discard, response.Body, 2048)
	response.Body.Close()
	return s
}
