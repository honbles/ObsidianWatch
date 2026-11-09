package api

import (
	"net/http"
	"sync"
	"time"
)

// cachedGET wraps an expensive, user-independent GET handler with a short
// TTL cache keyed by the query string (F-29: dashboard stats ran a dozen
// COUNT(*) queries on every request). Only 200 responses are cached; the
// cache is bounded (reset when it exceeds 64 keys).
func cachedGET(ttl time.Duration, next http.HandlerFunc) http.HandlerFunc {
	type entry struct {
		body    []byte
		ctype   string
		expires time.Time
	}
	var mu sync.Mutex
	cache := map[string]entry{}

	return func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.RawQuery
		mu.Lock()
		if e, ok := cache[key]; ok && time.Now().Before(e.expires) {
			mu.Unlock()
			if e.ctype != "" {
				w.Header().Set("Content-Type", e.ctype)
			}
			w.Header().Set("X-Cache", "HIT")
			w.WriteHeader(http.StatusOK)
			w.Write(e.body)
			return
		}
		mu.Unlock()

		rec := &bufRecorder{header: http.Header{}, status: http.StatusOK}
		next(rec, r)

		for k, v := range rec.header {
			w.Header()[k] = v
		}
		w.WriteHeader(rec.status)
		w.Write(rec.buf)

		if rec.status == http.StatusOK {
			mu.Lock()
			if len(cache) > 64 {
				cache = map[string]entry{}
			}
			cache[key] = entry{body: rec.buf, ctype: rec.header.Get("Content-Type"), expires: time.Now().Add(ttl)}
			mu.Unlock()
		}
	}
}

type bufRecorder struct {
	header http.Header
	status int
	buf    []byte
}

func (b *bufRecorder) Header() http.Header         { return b.header }
func (b *bufRecorder) WriteHeader(code int)        { b.status = code }
func (b *bufRecorder) Write(p []byte) (int, error) { b.buf = append(b.buf, p...); return len(p), nil }
