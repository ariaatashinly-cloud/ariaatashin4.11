package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/html"
)

type ImageChoice struct {
	ID      string    `json:"id"`
	Title   string    `json:"title"`
	Author  string    `json:"author"`
	License string    `json:"license"`
	Source  string    `json:"source"`
	URL     string    `json:"-"`
	Expires time.Time `json:"-"`
}

func plainImageText(raw string) string {
	t := html.NewTokenizer(strings.NewReader(raw))
	var out strings.Builder
	for {
		kind := t.Next()
		if kind == html.ErrorToken {
			break
		}
		if kind == html.TextToken {
			out.Write(t.Text())
		}
	}
	s := strings.TrimSpace(out.String())
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}
func wikiAssetURL(raw string) bool {
	u, e := url.Parse(raw)
	return e == nil && u.Scheme == "https" && (u.Host == "upload.wikimedia.org" || u.Host == "thumb.wikimedia.org") && u.User == nil && u.Fragment == ""
}
func (a *App) imageClient() *http.Client {
	if a.imageHTTP != nil {
		return a.imageHTTP
	}
	return &http.Client{Timeout: 15 * time.Second, CheckRedirect: noRedirect}
}
func (a *App) imagesAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		apiError(w, 405, "GET required")
		return
	}
	if r.URL.Path == "/api/images/search" {
		q := strings.TrimSpace(r.URL.Query().Get("q"))
		if len(q) < 2 || len(q) > 120 {
			apiError(w, 400, "عبارت جست‌وجوی ۲ تا ۱۲۰ حرفی وارد کن")
			return
		}
		values := url.Values{"action": {"query"}, "format": {"json"}, "formatversion": {"2"}, "generator": {"search"}, "gsrsearch": {q + " filetype:bitmap"}, "gsrnamespace": {"6"}, "gsrlimit": {"12"}, "prop": {"imageinfo"}, "iiprop": {"url|extmetadata"}, "iiurlwidth": {"1280"}, "iiextmetadatafilter": {"Artist|LicenseShortName"}}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, "GET", "https://commons.wikimedia.org/w/api.php?"+values.Encode(), nil)
		req.Header.Set("User-Agent", "ariaatashin/4.9 (background selector; https://commons.wikimedia.org)")
		resp, e := a.imageClient().Do(req)
		if e != nil {
			apiError(w, 502, "جست‌وجوی عکس در دسترس نیست؛ دوباره امتحان کن یا تصویر را آپلود کن")
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			apiError(w, 502, "سرویس تصویر فعلاً پاسخ نمی‌دهد؛ آپلود شخصی همچنان قابل استفاده است")
			return
		}
		var data struct {
			Query struct {
				Pages []struct {
					Title     string `json:"title"`
					ImageInfo []struct {
						ThumbURL       string `json:"thumburl"`
						DescriptionURL string `json:"descriptionurl"`
						Metadata       map[string]struct {
							Value string `json:"value"`
						} `json:"extmetadata"`
					} `json:"imageinfo"`
				} `json:"pages"`
			} `json:"query"`
		}
		if json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&data) != nil {
			apiError(w, 502, "پاسخ جست‌وجو خوانده نشد")
			return
		}
		items := []ImageChoice{}
		now := time.Now()
		a.imageMu.Lock()
		defer a.imageMu.Unlock()
		if a.imageChoices == nil {
			a.imageChoices = map[string]ImageChoice{}
		}
		for k, v := range a.imageChoices {
			if now.After(v.Expires) {
				delete(a.imageChoices, k)
			}
		}
		if len(a.imageChoices) > 256 {
			a.imageChoices = map[string]ImageChoice{}
		}
		for _, page := range data.Query.Pages {
			if len(page.ImageInfo) == 0 {
				continue
			}
			v := page.ImageInfo[0]
			source, e := url.Parse(v.DescriptionURL)
			if !wikiAssetURL(v.ThumbURL) || e != nil || source.Scheme != "https" || source.Host != "commons.wikimedia.org" {
				continue
			}
			item := ImageChoice{ID: randomToken(16), Title: plainImageText(strings.TrimPrefix(page.Title, "File:")), Author: plainImageText(v.Metadata["Artist"].Value), License: plainImageText(v.Metadata["LicenseShortName"].Value), Source: source.String(), URL: v.ThumbURL, Expires: now.Add(15 * time.Minute)}
			a.imageChoices[item.ID] = item
			items = append(items, item)
		}
		jsonReply(w, 200, map[string]any{"items": items, "provider": "Wikimedia Commons", "note": "مجوز و سازنده همراه تصویر نمایش داده می‌شوند. جست‌وجوی انگلیسی معمولاً نتیجهٔ بیشتری دارد."})
		return
	}
	if r.URL.Path == "/api/images/preview" {
		a.imageMu.Lock()
		v, ok := a.imageChoices[r.URL.Query().Get("id")]
		a.imageMu.Unlock()
		if !ok || time.Now().After(v.Expires) || !wikiAssetURL(v.URL) {
			apiError(w, 404, "تصویر منقضی شده؛ دوباره جست‌وجو کن")
			return
		}
		req, _ := http.NewRequestWithContext(r.Context(), "GET", v.URL, nil)
		req.Header.Set("User-Agent", "ariaatashin/4.9 background selector")
		resp, e := a.imageClient().Do(req)
		if e != nil {
			apiError(w, 502, "تصویر در دسترس نیست")
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			apiError(w, 502, "دریافت تصویر ناموفق بود")
			return
		}
		b, e := io.ReadAll(io.LimitReader(resp.Body, 12<<20+1))
		if e != nil || len(b) > 12<<20 {
			apiError(w, 413, "تصویر بیش از حد بزرگ است")
			return
		}
		mime := http.DetectContentType(b)
		if mime != "image/jpeg" && mime != "image/png" && mime != "image/webp" {
			apiError(w, 415, "قالب تصویر پشتیبانی نمی‌شود")
			return
		}
		w.Header().Set("Content-Type", mime)
		w.Header().Set("Cache-Control", "private, max-age=300")
		_, _ = w.Write(b)
		return
	}
	apiError(w, 404, fmt.Sprint("image action not found"))
}
