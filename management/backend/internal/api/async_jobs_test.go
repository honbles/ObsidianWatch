package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAsyncJobRunsDetachedAndKeepsPathValues(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /scan/{id}", asyncJob(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		writeJSON(w, 200, map[string]string{"id": r.PathValue("id")})
	}))
	mux.HandleFunc("GET /jobs/{id}", handleGetJob())

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("POST", "/scan/42?async=1", nil))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("want 202, got %d", rec.Code)
	}
	var acc struct{ JobID string `json:"job_id"` }
	_ = json.Unmarshal(rec.Body.Bytes(), &acc)
	if acc.JobID == "" {
		t.Fatal("no job id")
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		r2 := httptest.NewRecorder()
		mux.ServeHTTP(r2, httptest.NewRequest("GET", "/jobs/"+acc.JobID, nil))
		var st struct {
			Status string            `json:"status"`
			Result map[string]string `json:"result"`
		}
		_ = json.Unmarshal(r2.Body.Bytes(), &st)
		if st.Status == "done" {
			if st.Result["id"] != "42" {
				t.Fatalf("path value lost: %+v", st.Result)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("job did not finish")
}
