package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"obsidianwatch/management/internal/auth"
	"sync"
	"time"
)

// G-45: long cloud scans (CSPM, CIS, compliance, blast radius) used to hold
// the HTTP request open for up to 3 minutes. Wrapping a route with asyncJob
// lets a client opt in with ?async=1: the handler then runs detached, the
// call returns 202 + job_id immediately, and GET /api/v1/jobs/{id} reports
// status and the handler's response. Without ?async=1 behaviour is unchanged.
// State is in memory (jobs are minutes long and re-runnable); results of the
// scans themselves are still persisted by the handlers as before.

const (
	jobMaxRuntime = 10 * time.Minute
	jobKeepFor    = 30 * time.Minute
)

type asyncJobState struct {
	ID        string      `json:"id"`
	Key       string      `json:"key"`
	Owner     string      `json:"-"`
	Status    string      `json:"status"` // running | done | failed
	HTTPCode  int         `json:"http_status,omitempty"`
	Result    interface{} `json:"result,omitempty"`
	Error     string      `json:"error,omitempty"`
	StartedAt time.Time   `json:"started_at"`
	EndedAt   *time.Time  `json:"ended_at,omitempty"`
}

var (
	jobsMu    sync.Mutex
	jobsByID  = map[string]*asyncJobState{}
	jobsByKey = map[string]string{} // running job per route+resource
)

func newJobID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func pruneJobsLocked() {
	cut := time.Now().Add(-jobKeepFor)
	for id, j := range jobsByID {
		if j.EndedAt != nil && j.EndedAt.Before(cut) {
			delete(jobsByID, id)
		}
	}
}

func asyncJob(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("async") != "1" {
			next(w, r)
			return
		}
		key := r.Method + " " + r.URL.Path
		jobsMu.Lock()
		pruneJobsLocked()
		if id, running := jobsByKey[key]; running {
			j := jobsByID[id]
			jobsMu.Unlock()
			writeJSON(w, http.StatusAccepted, map[string]interface{}{"job_id": id, "status": j.Status, "already_running": true})
			return
		}
		j := &asyncJobState{ID: newJobID(), Key: key, Status: "running", StartedAt: time.Now()}
		if c := claimsUsername(r); c != "" {
			j.Owner = c
		}
		jobsByID[j.ID] = j
		jobsByKey[key] = j.ID
		jobsMu.Unlock()

		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), jobMaxRuntime)
		r2 := r.Clone(ctx)
		go func() {
			defer cancel()
			rec := httptest.NewRecorder()
			func() {
				defer func() {
					if p := recover(); p != nil {
						rec.Code = http.StatusInternalServerError
						rec.Body.Reset()
						rec.Body.WriteString(`{"error":"job panicked"}`)
					}
				}()
				next(rec, r2)
			}()
			end := time.Now()
			jobsMu.Lock()
			defer jobsMu.Unlock()
			j.EndedAt = &end
			j.HTTPCode = rec.Code
			body := rec.Body.Bytes()
			if rec.Code >= 400 {
				j.Status = "failed"
				j.Error = string(body)
			} else {
				j.Status = "done"
				j.Result = jsonRaw(body)
			}
			delete(jobsByKey, key)
		}()
		writeJSON(w, http.StatusAccepted, map[string]interface{}{"job_id": j.ID, "status": "running"})
	}
}

type jsonRaw []byte

func (b jsonRaw) MarshalJSON() ([]byte, error) {
	if len(b) == 0 {
		return []byte("null"), nil
	}
	return b, nil
}

// handleGetJob: GET /api/v1/jobs/{id}
func handleGetJob() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jobsMu.Lock()
		j, ok := jobsByID[r.PathValue("id")]
		var cp asyncJobState
		if ok {
			cp = *j
		}
		jobsMu.Unlock()
		if !ok {
			writeJSONError(w, http.StatusNotFound, "job not found or expired")
			return
		}
		writeJSON(w, http.StatusOK, cp)
	}
}

func claimsUsername(r *http.Request) string {
	if c := auth.GetClaims(r); c != nil {
		return c.Username
	}
	return ""
}
