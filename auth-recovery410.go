package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Read the existing native 2FA policy locally, so an unavailable process cannot
// lock the operator out or silently disable a previously enabled second factor.
func (a *App) nativeOTPSecret(ctx context.Context) (string, error) {
	path := filepath.Join(a.cfg.DataDir, "x-ui.db")
	if _, e := os.Stat(path); os.IsNotExist(e) {
		return "", nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	b, e := exec.CommandContext(ctx, "sqlite3", "-readonly", "-json", path, "SELECT key,value FROM settings WHERE key IN ('twoFactorEnable','twoFactorToken');").Output()
	if e != nil {
		return "", fmt.Errorf("خواندن سیاست ورود دومرحله‌ای انجام نشد؛ sqlite3 و پوشهٔ داده را بررسی کن")
	}
	if strings.TrimSpace(string(b)) == "" {
		return "", nil
	}
	var rows []struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	if json.Unmarshal(b, &rows) != nil {
		return "", fmt.Errorf("تنظیمات ورود دومرحله‌ای خوانده نشد")
	}
	enabled, secret := false, ""
	for _, v := range rows {
		if v.Key == "twoFactorEnable" {
			var parseErr error
			enabled, parseErr = strconv.ParseBool(v.Value)
			if parseErr != nil {
				return "", fmt.Errorf("سیاست ورود دومرحله‌ای معتبر نیست")
			}
		}
		if v.Key == "twoFactorToken" {
			secret = v.Value
		}
	}
	if !enabled {
		return "", nil
	}
	if _, e := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimRight(strings.TrimSpace(secret), "="))); e != nil || secret == "" {
		return "", fmt.Errorf("کلید ورود دومرحله‌ای معتبر نیست")
	}
	return secret, nil
}
func nativeTOTP(secret string, at time.Time) string {
	key, e := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimRight(strings.TrimSpace(secret), "=")))
	if e != nil {
		return ""
	}
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(at.Unix()/30))
	h := hmac.New(sha1.New, key)
	h.Write(b)
	v := h.Sum(nil)
	n := v[len(v)-1] & 15
	code := binary.BigEndian.Uint32(v[n:n+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", code%1000000)
}
func validNativeOTP(secret, code string, at time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}
	ok := 0
	for _, d := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
		ok |= subtle.ConstantTimeCompare([]byte(code), []byte(nativeTOTP(secret, at.Add(d))))
	}
	return ok == 1
}
func (a *App) coreEngineClient() *EngineClient {
	e := newEngineClient(a.base)
	e.username = a.cfg.AdminUser
	e.password = a.cfg.AdminPassword
	e.autoLogin = true
	e.otpCode = func() (string, error) {
		s, err := a.nativeOTPSecret(context.Background())
		if err != nil {
			return "", err
		}
		if s == "" {
			return "", nil
		}
		return nativeTOTP(s, time.Now()), nil
	}
	return e
}
func (a *App) renewPanelSession(w http.ResponseWriter, r *http.Request, s session, origin string) {
	if time.Until(s.Expires) > 6*time.Hour {
		return
	}
	c, e := r.Cookie("atia_session")
	if e != nil {
		return
	}
	a.mu.Lock()
	current, ok := a.sessions[c.Value]
	if ok {
		current.Expires = time.Now().Add(12 * time.Hour)
		a.sessions[c.Value] = current
	}
	a.mu.Unlock()
	if ok {
		http.SetCookie(w, &http.Cookie{Name: "atia_session", Value: c.Value, Path: "/", HttpOnly: true, Secure: strings.HasPrefix(origin, "https:"), SameSite: http.SameSiteStrictMode, MaxAge: 12 * 3600})
	}
}
