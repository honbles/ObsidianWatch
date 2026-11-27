package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

// CodeScanJob is one queued or finished automated code scan.
type CodeScanJob struct {
	ID           int64           `json:"id"`
	ConnectorID  int64           `json:"connector_id"`
	Kind         string          `json:"kind"`
	Trigger      string          `json:"trigger"`
	Repo         string          `json:"repo"`
	Ref          string          `json:"ref"`
	BaseBranch   string          `json:"base_branch,omitempty"`
	HeadRef      string          `json:"head_ref,omitempty"`
	HeadSHA      string          `json:"head_sha,omitempty"`
	Status       string          `json:"status"`
	Blocked      bool            `json:"blocked"`
	FindingCount int             `json:"finding_count"`
	Error        *string         `json:"error,omitempty"`
	Result       json.RawMessage `json:"result,omitempty"`
	CreatedAt    time.Time       `json:"created_at"`
	StartedAt    *time.Time      `json:"started_at,omitempty"`
	FinishedAt   *time.Time      `json:"finished_at,omitempty"`
	// Payload: job-specific input (the PR comment for kind "agent").
	Payload json.RawMessage `json:"payload,omitempty"`
}

// EnqueueCodeScanJob queues a job unless the same target and commit is
// already queued or running. Returns the job ID (0 when it was a duplicate).
func (db *DB) EnqueueCodeScanJob(ctx context.Context, j CodeScanJob) (int64, error) {
	var id int64
	err := db.QueryRowContext(ctx, `
		INSERT INTO code_scan_jobs (connector_id, kind, trigger, repo, ref, base_branch, head_ref, head_sha, payload)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (connector_id, kind, repo, ref, head_sha) WHERE status IN ('queued','running') DO NOTHING
		RETURNING id`,
		j.ConnectorID, j.Kind, j.Trigger, j.Repo, j.Ref, j.BaseBranch, j.HeadRef, j.HeadSHA, nullRaw(j.Payload)).Scan(&id)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return id, err
}

// ClaimCodeScanJob marks the oldest queued job running and returns it.
func (db *DB) ClaimCodeScanJob(ctx context.Context) (*CodeScanJob, error) {
	row := db.QueryRowContext(ctx, `
		UPDATE code_scan_jobs SET status='running', started_at=NOW()
		WHERE id = (SELECT id FROM code_scan_jobs WHERE status='queued' ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1)
		RETURNING `+codeJobCols)
	j, err := scanCodeJob(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return j, err
}

// FinishCodeScanJob records the outcome of a job.
func (db *DB) FinishCodeScanJob(ctx context.Context, id int64, status string, blocked bool, findings int, errMsg string, result []byte) error {
	var e interface{}
	if errMsg != "" {
		e = errMsg
	}
	var res interface{}
	if len(result) > 0 {
		res = result
	}
	_, err := db.ExecContext(ctx, `
		UPDATE code_scan_jobs SET status=$2, blocked=$3, finding_count=$4, error=$5, result=$6, finished_at=NOW()
		WHERE id=$1`, id, status, blocked, findings, e, res)
	return err
}

// FailStaleCodeScanJobs fails jobs left running by a restart.
func (db *DB) FailStaleCodeScanJobs(ctx context.Context, olderThan time.Duration) {
	_, _ = db.ExecContext(ctx, `
		UPDATE code_scan_jobs SET status='failed', error='interrupted (server restart)', finished_at=NOW()
		WHERE status='running' AND started_at < NOW() - make_interval(secs => $1)`, olderThan.Seconds())
}

// ListCodeScanJobs returns a connector's recent jobs, newest first, without results.
func (db *DB) ListCodeScanJobs(ctx context.Context, connID int64, limit int) ([]CodeScanJob, error) {
	rows, err := db.QueryContext(ctx, `SELECT `+codeJobColsNoResult+` FROM code_scan_jobs
		WHERE connector_id=$1 ORDER BY id DESC LIMIT $2`, connID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CodeScanJob{}
	for rows.Next() {
		j, err := scanCodeJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *j)
	}
	return out, rows.Err()
}

// GetCodeScanJob returns one job with its result.
func (db *DB) GetCodeScanJob(ctx context.Context, id int64) (*CodeScanJob, error) {
	return scanCodeJob(db.QueryRowContext(ctx, `SELECT `+codeJobCols+` FROM code_scan_jobs WHERE id=$1`, id))
}

const codeJobColsNoResult = `id, connector_id, kind, trigger, repo, ref, base_branch, head_ref, head_sha, status, blocked,
	finding_count, error, NULL::jsonb, created_at, started_at, finished_at, payload`
const codeJobCols = `id, connector_id, kind, trigger, repo, ref, base_branch, head_ref, head_sha, status, blocked,
	finding_count, error, result, created_at, started_at, finished_at, payload`

type rowScanner interface {
	Scan(dest ...interface{}) error
}

func scanCodeJob(r rowScanner) (*CodeScanJob, error) {
	var j CodeScanJob
	var result, payload []byte
	if err := r.Scan(&j.ID, &j.ConnectorID, &j.Kind, &j.Trigger, &j.Repo, &j.Ref, &j.BaseBranch, &j.HeadRef, &j.HeadSHA,
		&j.Status, &j.Blocked, &j.FindingCount, &j.Error, &result, &j.CreatedAt, &j.StartedAt, &j.FinishedAt, &payload); err != nil {
		return nil, err
	}
	if len(payload) > 0 {
		j.Payload = payload
	}
	if len(result) > 0 {
		j.Result = result
	}
	return &j, nil
}

func nullRaw(b json.RawMessage) interface{} {
	if len(b) == 0 {
		return nil
	}
	return []byte(b)
}

// EnsureDevOpsWebhookSecret sets a connector's webhook secret when it has
// none and returns the effective (opened) secret.
func (db *DB) EnsureDevOpsWebhookSecret(ctx context.Context, id int64, candidate string) (string, error) {
	var stored string
	err := db.QueryRowContext(ctx, `UPDATE devops_connectors SET webhook_secret =
		CASE WHEN COALESCE(webhook_secret,'') = '' THEN $2 ELSE webhook_secret END
		WHERE id=$1 RETURNING COALESCE(webhook_secret,'')`, id, sealString(candidate)).Scan(&stored)
	if err != nil {
		return "", err
	}
	return openString(stored), nil
}

// PRCheckState is what was last reported on a pull/merge request.
type PRCheckState struct {
	LastSHA   string
	LastState string
	Commented map[string]bool
}

func (db *DB) GetPRCheckState(ctx context.Context, connID int64, repo, pr string) PRCheckState {
	st := PRCheckState{Commented: map[string]bool{}}
	var keys []byte
	if err := db.QueryRowContext(ctx, `SELECT last_sha, last_state, commented FROM code_pr_checks
		WHERE connector_id=$1 AND repo=$2 AND pr=$3`, connID, repo, pr).Scan(&st.LastSHA, &st.LastState, &keys); err != nil {
		return st
	}
	var list []string
	_ = json.Unmarshal(keys, &list)
	for _, k := range list {
		st.Commented[k] = true
	}
	return st
}

func (db *DB) SavePRCheckState(ctx context.Context, connID int64, repo, pr string, st PRCheckState) error {
	list := make([]string, 0, len(st.Commented))
	for k := range st.Commented {
		list = append(list, k)
	}
	if len(list) > 2000 {
		list = list[len(list)-2000:]
	}
	b, _ := json.Marshal(list)
	_, err := db.ExecContext(ctx, `
		INSERT INTO code_pr_checks (connector_id, repo, pr, last_sha, last_state, commented, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,NOW())
		ON CONFLICT (connector_id, repo, pr) DO UPDATE SET
			last_sha=EXCLUDED.last_sha, last_state=EXCLUDED.last_state, commented=EXCLUDED.commented, updated_at=NOW()`,
		connID, repo, pr, st.LastSHA, st.LastState, b)
	return err
}
