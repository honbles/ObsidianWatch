package response

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	defaultQueryRows = 500
	maxQueryRows     = 5000
	fileWalkBudget   = 25 * time.Second
	fileWalkMax      = 400000
	hashMaxBytes     = 100 << 20
)

// QueryKinds lists the fixed, read-only questions a fleet hunt can ask.
// There is no arbitrary command execution here by design.
var QueryKinds = []string{"processes", "connections", "listening", "persistence", "software", "users", "file_find"}

func (h *Handler) query(ctx context.Context, p Params) Result {
	limit := p.Limit
	if limit <= 0 || limit > maxQueryRows {
		limit = defaultQueryRows
	}
	var (
		cols []string
		rows [][]string
		err  error
	)
	switch p.Kind {
	case "processes":
		cols, rows, err = qProcesses(ctx)
	case "connections":
		cols, rows, err = qConnections(ctx)
	case "listening":
		cols, rows, err = qConnections(ctx)
		rows = keepRows(cols, rows, "state", func(v string) bool {
			v = strings.ToUpper(v)
			return v == "LISTEN" || v == "LISTENING" || v == "UNCONN"
		})
	case "persistence":
		cols, rows, err = qPersistence(ctx)
	case "software":
		cols, rows, err = qSoftware(ctx)
	case "users":
		cols, rows, err = qUsers(ctx)
	case "file_find":
		return h.fileFind(ctx, p, limit)
	default:
		return Result{Message: "unknown query kind " + p.Kind}
	}
	if err != nil {
		return Result{Message: err.Error()}
	}
	t := filterTable(cols, rows, p.Match, limit)
	return Result{OK: true, Message: fmt.Sprintf("%d row(s)", len(t.Rows)), Data: t}
}

func keepRows(cols []string, rows [][]string, col string, ok func(string) bool) [][]string {
	idx := -1
	for i, c := range cols {
		if c == col {
			idx = i
		}
	}
	if idx < 0 {
		return rows
	}
	out := rows[:0:0]
	for _, r := range rows {
		if idx < len(r) && ok(r[idx]) {
			out = append(out, r)
		}
	}
	return out
}

// filterTable applies a case-insensitive match. "col:text" restricts the match
// to one column; several terms separated by spaces must all match.
func filterTable(cols []string, rows [][]string, match string, limit int) Table {
	t := Table{Columns: cols, Rows: [][]string{}}
	terms := strings.Fields(strings.ToLower(match))
	for _, r := range rows {
		ok := true
		for _, term := range terms {
			col, val := "", term
			if i := strings.IndexByte(term, ':'); i > 0 {
				for _, c := range cols {
					if strings.ToLower(c) == term[:i] {
						col, val = c, term[i+1:]
					}
				}
			}
			hit := false
			for i, cell := range r {
				if col != "" && cols[i] != col {
					continue
				}
				if strings.Contains(strings.ToLower(cell), val) {
					hit = true
					break
				}
			}
			if !hit {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		if len(t.Rows) >= limit {
			t.Truncated = true
			break
		}
		t.Rows = append(t.Rows, r)
	}
	return t
}

var skipDirs = map[string]bool{"/proc": true, "/sys": true, "/dev": true, "/run": true, "/snap": true, "/System/Volumes/Data/private/var/vm": true}

// fileFind walks a directory tree looking for a file name substring or an
// exact SHA-256 ("sha256:<hex>"), within a time and entry budget.
func (h *Handler) fileFind(ctx context.Context, p Params, limit int) Result {
	root := p.Path
	if root == "" {
		if runtime.GOOS == "windows" {
			root = `C:\Users`
		} else {
			root = "/"
		}
	}
	if !filepath.IsAbs(root) {
		return Result{Message: "path must be absolute"}
	}
	needle := strings.TrimSpace(p.Match)
	if needle == "" {
		return Result{Message: "match required (file name text, or sha256:<hash>)"}
	}
	wantHash := ""
	if strings.HasPrefix(strings.ToLower(needle), "sha256:") {
		wantHash = strings.ToLower(strings.TrimSpace(needle[7:]))
		if len(wantHash) != 64 {
			return Result{Message: "sha256 must be 64 hex characters"}
		}
	}
	low := strings.ToLower(needle)
	deadline := time.Now().Add(fileWalkBudget)
	t := Table{Columns: []string{"path", "size", "modified", "sha256"}, Rows: [][]string{}}
	seen := 0
	stopped := ""
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil || time.Now().After(deadline) {
			stopped = "time budget reached"
			return fs.SkipAll
		}
		if seen++; seen > fileWalkMax {
			stopped = "entry budget reached"
			return fs.SkipAll
		}
		if d.IsDir() {
			if skipDirs[path] {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		sum := ""
		if wantHash != "" {
			if info.Size() > hashMaxBytes {
				return nil
			}
			s, _, err := hashFile(path)
			if err != nil || s != wantHash {
				return nil
			}
			sum = s
		} else {
			if !strings.Contains(strings.ToLower(d.Name()), low) {
				return nil
			}
			if info.Size() <= hashMaxBytes && len(t.Rows) < 50 {
				sum, _, _ = hashFile(path)
			}
		}
		if len(t.Rows) >= limit {
			t.Truncated = true
			return fs.SkipAll
		}
		t.Rows = append(t.Rows, []string{path, fmt.Sprint(info.Size()), info.ModTime().UTC().Format(time.RFC3339), sum})
		return nil
	})
	msg := fmt.Sprintf("%d file(s) under %s", len(t.Rows), root)
	if stopped != "" {
		msg += " (" + stopped + "; narrow the path)"
		t.Truncated = true
	}
	return Result{OK: true, Message: msg, Data: t}
}

func baseOf(s string) string {
	s = strings.ReplaceAll(s, `\`, "/")
	return filepath.Base(s)
}

var _ = os.Getpid
